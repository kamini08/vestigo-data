"""
Advanced Address-Aware GNN for Cryptographic Function Detection
=================================================================

This module implements a comprehensive Graph Neural Network (GNN) for detecting
cryptographic functions in binary code. It uses:
1. Address-based features (spatial patterns, jump distances, locality)
2. Control flow graph structure (nodes = basic blocks, edges = control flow)
3. Advanced crypto-specific features (S-boxes, constants, patterns)
4. Multi-level features (node, edge, graph)

Pipeline:
    JSON → Graph Construction → GNN Training → Inference → Output JSON
"""

import json
import glob
import os
import pickle
import warnings
from pathlib import Path
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score, precision_recall_fscore_support
)
from sklearn.preprocessing import LabelEncoder, StandardScaler

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from torch_geometric.data import Data, Batch
from torch_geometric.nn import (
    GCNConv, GATConv, SAGEConv, GINConv,
    global_mean_pool, global_max_pool, global_add_pool,
    BatchNorm, GraphNorm
)
from torch_geometric.utils import degree

warnings.filterwarnings('ignore')

# Set random seeds for reproducibility
torch.manual_seed(42)
np.random.seed(42)


# ============================================================================
# PART 1: DATA LOADING AND PREPROCESSING
# ============================================================================

class AddressFeatureExtractor:
    """
    Extracts advanced address-based features from binary code.

    Address features capture spatial patterns, code locality, and
    memory layout information that's crucial for crypto detection.
    """

    @staticmethod
    def normalize_address(address: str) -> str:
        """
        Normalize address format to plain hex string.

        Handles formats:
        - "00010000" → "00010000"
        - "code:010000" → "010000"
        - "CODE:ABCDEF" → "ABCDEF"
        - "0x10000" → "10000"

        Args:
            address: Address in various formats

        Returns:
            Normalized hex string
        """
        # Handle code: prefix (case-insensitive)
        if address.lower().startswith('code:'):
            address = address[5:]  # Remove "code:" prefix
        # Handle 0x prefix
        if address.startswith('0x') or address.startswith('0X'):
            address = address[2:]  # Remove "0x" prefix
        return address

    @staticmethod
    def extract_address_features(address: str) -> Dict[str, float]:
        """
        Extract multiple features from a hexadecimal address.

        Args:
            address: Hex address string (e.g., "00010000", "code:010000")

        Returns:
            Dictionary of address features
        """
        # Normalize address format
        address = AddressFeatureExtractor.normalize_address(address)
        addr_int = int(address, 16)

        # Basic address properties
        features = {
            'addr_value_normalized': addr_int / 0xFFFFFFFF,  # Normalize to [0,1]
            'addr_alignment_4': float(addr_int % 4 == 0),
            'addr_alignment_8': float(addr_int % 8 == 0),
            'addr_alignment_16': float(addr_int % 16 == 0),

            # Memory section detection (heuristic-based)
            'is_text_section': float(0x8000 <= addr_int < 0x100000),
            'is_data_section': float(0x100000 <= addr_int < 0x200000),
            'is_bss_section': float(0x200000 <= addr_int < 0x300000),

            # Address entropy (randomness measure)
            'addr_entropy': AddressFeatureExtractor._calculate_hex_entropy(address),

            # Bit patterns
            'addr_ones_ratio': bin(addr_int).count('1') / 32,  # Ratio of 1s in binary
            'addr_nibble_variety': len(set(address)) / 16,  # Hex digit diversity
        }

        return features

    @staticmethod
    def _calculate_hex_entropy(hex_string: str) -> float:
        """Calculate Shannon entropy of hex string."""
        if not hex_string:
            return 0.0

        # Normalize the hex string
        hex_string = AddressFeatureExtractor.normalize_address(hex_string)
        freq = Counter(hex_string)
        length = len(hex_string)

        entropy = -sum((count/length) * np.log2(count/length)
                      for count in freq.values() if count > 0)

        # Normalize by max possible entropy (log2(16) for hex)
        return entropy / 4.0 if length > 0 else 0.0

    @staticmethod
    def compute_edge_address_features(src_addr: str, dst_addr: str) -> Dict[str, float]:
        """
        Compute address-based features for control flow edges.

        Args:
            src_addr: Source basic block address (e.g., "00010000", "code:010000")
            dst_addr: Destination basic block address

        Returns:
            Dictionary of edge address features
        """
        # Normalize addresses
        src_addr = AddressFeatureExtractor.normalize_address(src_addr)
        dst_addr = AddressFeatureExtractor.normalize_address(dst_addr)

        src_int = int(src_addr, 16)
        dst_int = int(dst_addr, 16)

        jump_distance = dst_int - src_int
        abs_distance = abs(jump_distance)

        features = {
            'jump_distance': jump_distance,
            'abs_jump_distance': abs_distance,
            'jump_distance_log': np.log1p(abs_distance),  # Log scale for large jumps

            # Jump direction
            'is_forward_jump': float(jump_distance > 0),
            'is_backward_jump': float(jump_distance < 0),
            'is_short_jump': float(abs_distance < 256),  # Within 256 bytes
            'is_long_jump': float(abs_distance > 4096),  # Cross-function likely

            # Alignment preservation
            'alignment_preserved': float((src_int % 16) == (dst_int % 16)),

            # Section crossing (heuristic)
            'crosses_section': float(abs_distance > 0x10000),
        }

        return features

    @staticmethod
    def compute_graph_address_features(addresses: List[str]) -> Dict[str, float]:
        """
        Compute global address features for entire function graph.

        Args:
            addresses: List of all basic block addresses in function

        Returns:
            Dictionary of graph-level address features
        """
        if not addresses:
            return {f'graph_addr_{k}': 0.0 for k in [
                'span', 'density', 'avg_gap', 'locality_score'
            ]}

        # Normalize all addresses
        normalized_addresses = [AddressFeatureExtractor.normalize_address(addr) for addr in addresses]
        addr_ints = sorted([int(addr, 16) for addr in normalized_addresses])

        # Address span (range of addresses)
        span = addr_ints[-1] - addr_ints[0] if len(addr_ints) > 1 else 0

        # Address density (blocks per address unit)
        density = len(addr_ints) / (span + 1) if span > 0 else 1.0

        # Average gap between consecutive blocks
        gaps = [addr_ints[i+1] - addr_ints[i] for i in range(len(addr_ints)-1)]
        avg_gap = np.mean(gaps) if gaps else 0

        # Locality score (how tightly packed are blocks)
        locality_score = 1.0 / (1.0 + np.log1p(avg_gap))

        return {
            'graph_addr_span': span,
            'graph_addr_span_log': np.log1p(span),
            'graph_addr_density': density,
            'graph_addr_avg_gap': avg_gap,
            'graph_addr_locality_score': locality_score,
        }


class GraphDataset(Dataset):
    """
    PyTorch Dataset for graph-structured binary function data.

    Each sample is a function represented as a graph:
    - Nodes: Basic blocks with instruction features
    - Edges: Control flow with branch features
    - Graph: Function-level statistics
    """

    def __init__(self, json_files: List[str], label_encoder: Optional[LabelEncoder] = None):
        """
        Initialize dataset from JSON files.

        Args:
            json_files: List of paths to feature JSON files
            label_encoder: Pre-fitted LabelEncoder (for test set)
        """
        self.graphs = []
        self.labels = []
        self.metadata = []

        # Initialize label encoder
        if label_encoder is None:
            self.label_encoder = LabelEncoder()
            self.fit_labels = True
        else:
            self.label_encoder = label_encoder
            self.fit_labels = False

        # Initialize feature scalers
        self.node_scaler = StandardScaler()
        self.edge_scaler = StandardScaler()
        self.graph_scaler = StandardScaler()

        # Load and process all JSON files
        print(f"Loading {len(json_files)} JSON files...")
        all_labels = []

        for json_file in tqdm(json_files, desc="Loading data"):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                binary_info = data.get('binary', {})

                for func in data['functions']:
                    if 'label' not in func:
                        continue  # Skip unlabeled functions

                    graph_data = self._function_to_graph(func, binary_info)

                    if graph_data is not None:
                        self.graphs.append(graph_data)
                        all_labels.append(func['label'])
                        self.metadata.append({
                            'address': func['address'],
                            'name': func.get('name', 'unknown'),
                            'source_file': os.path.basename(json_file)
                        })

            except Exception as e:
                print(f"Error loading {json_file}: {e}")
                continue

        # Fit label encoder on training data
        if self.fit_labels and all_labels:
            self.label_encoder.fit(all_labels)

        # Encode labels
        self.labels = self.label_encoder.transform(all_labels)

        # Fit scalers on collected features
        self._fit_scalers()

        print(f"\nDataset loaded: {len(self.graphs)} functions")
        print(f"Label distribution:")
        label_counts = Counter(all_labels)
        for label, count in label_counts.most_common():
            print(f"  {label}: {count}")

    def _function_to_graph(self, func: Dict, binary_info: Dict) -> Optional[Dict]:
        """
        Convert a function JSON to graph representation.

        Args:
            func: Function dictionary from JSON
            binary_info: Binary metadata

        Returns:
            Dictionary with graph components (nodes, edges, features)
        """
        try:
            # Extract nodes (basic blocks)
            node_level = func.get('node_level', [])
            if not node_level:
                return None

            # Build address to index mapping
            addresses = [node['address'] for node in node_level]
            addr_to_idx = {addr: idx for idx, addr in enumerate(addresses)}

            # Extract node features
            node_features = []
            for node in node_level:
                features = self._extract_node_features(node)
                node_features.append(features)

            # Extract edges
            edge_level = func.get('edge_level', [])
            edge_index = []
            edge_features = []

            for edge in edge_level:
                src_addr = edge['src']
                dst_addr = edge['dst']

                # Skip edges to external addresses
                if src_addr not in addr_to_idx or dst_addr not in addr_to_idx:
                    continue

                src_idx = addr_to_idx[src_addr]
                dst_idx = addr_to_idx[dst_addr]

                edge_index.append([src_idx, dst_idx])

                # Extract edge features
                edge_feat = self._extract_edge_features(edge, src_addr, dst_addr)
                edge_features.append(edge_feat)

            # Extract graph-level features
            graph_features = self._extract_graph_features(func, addresses)

            # Determine edge feature dimension (9 address features + 4 edge type features = 13)
            edge_feature_dim = 13

            return {
                'node_features': np.array(node_features, dtype=np.float32),
                'edge_index': np.array(edge_index, dtype=np.int64).T if edge_index else np.zeros((2, 0), dtype=np.int64),
                'edge_features': np.array(edge_features, dtype=np.float32) if edge_features else np.zeros((0, edge_feature_dim), dtype=np.float32),
                'graph_features': np.array(graph_features, dtype=np.float32),
                'num_nodes': len(node_level)
            }

        except Exception as e:
            print(f"Error processing function {func.get('address', 'unknown')}: {e}")
            return None

    def _extract_node_features(self, node: Dict) -> List[float]:
        """Extract feature vector from a basic block node."""
        features = []

        # Address-based features
        addr_features = AddressFeatureExtractor.extract_address_features(node['address'])
        features.extend(addr_features.values())

        # Basic block statistics
        features.extend([
            node.get('instruction_count', 0),
            node.get('crypto_constant_hits', 0),
            node.get('immediate_entropy', 0.0),
            node.get('bitwise_op_density', 0.0),
            node.get('n_gram_repetition', 0.0),
            float(node.get('simd_usage', False)),
            float(node.get('table_lookup_presence', False)),
        ])

        # Opcode ratios
        opcode_ratios = node.get('opcode_ratios', {})
        features.extend([
            opcode_ratios.get('add', 0.0),
            opcode_ratios.get('xor', 0.0),
            opcode_ratios.get('rotate', 0.0),
            opcode_ratios.get('logical', 0.0),
            opcode_ratios.get('load_store', 0.0),
            opcode_ratios.get('multiply', 0.0),
        ])

        # Immediate values statistics
        immediates = node.get('immediates', [])
        if immediates:
            features.extend([
                np.mean(immediates),
                np.std(immediates),
                np.max(immediates),
                np.min(immediates),
                len(set(immediates)),  # Unique immediates
            ])
        else:
            features.extend([0.0, 0.0, 0.0, 0.0, 0])

        return features

    def _extract_edge_features(self, edge: Dict, src_addr: str, dst_addr: str) -> List[float]:
        """Extract feature vector from a control flow edge."""
        features = []

        # Address-based edge features
        addr_features = AddressFeatureExtractor.compute_edge_address_features(src_addr, dst_addr)
        features.extend(addr_features.values())

        # Edge type features
        features.extend([
            edge.get('branch_condition_complexity', 0),
            float(edge.get('is_loop_edge', False)),
            float(edge.get('edge_type', '') == 'conditional'),
            float(edge.get('edge_type', '') == 'unconditional'),
        ])

        return features

    def _extract_graph_features(self, func: Dict, addresses: List[str]) -> List[float]:
        """Extract function-level graph features."""
        features = []

        # Address-based graph features
        addr_features = AddressFeatureExtractor.compute_graph_address_features(addresses)
        features.extend(addr_features.values())

        # Graph-level statistics
        graph_level = func.get('graph_level', {})
        features.extend([
            graph_level.get('num_basic_blocks', 0),
            graph_level.get('num_edges', 0),
            graph_level.get('cyclomatic_complexity', 0),
            graph_level.get('loop_count', 0),
            graph_level.get('loop_depth', 0),
            graph_level.get('num_conditional_edges', 0),
            graph_level.get('num_unconditional_edges', 0),
            graph_level.get('num_loop_edges', 0),
            graph_level.get('num_entry_exit_paths', 0),
            graph_level.get('strongly_connected_components', 0),
            graph_level.get('average_block_size', 0.0),
            graph_level.get('branch_density', 0.0),
            graph_level.get('avg_edge_branch_condition_complexity', 0.0),
        ])

        # Advanced crypto-specific features
        advanced = func.get('advanced_features', {})
        features.extend([
            float(advanced.get('has_aes_sbox', False)),
            float(advanced.get('has_aes_rcon', False)),
            advanced.get('aes_sbox_match_score', 0.0),
            advanced.get('mixcolumns_pattern_score', 0.0),
            float(advanced.get('key_expansion_detection', False)),
            advanced.get('approx_rounds', 0),
            advanced.get('schedule_size_detection', 0),

            advanced.get('sha_init_constants_hits', 0),
            advanced.get('sha_k_table_hits', 0),
            advanced.get('sha_rotation_patterns', 0),

            advanced.get('bigint_op_count', 0),
            advanced.get('bignum_limb_count', 0),
            advanced.get('bigint_width', 0),
            advanced.get('montgomery_op_count', 0),
            advanced.get('modexp_op_density', 0.0),
            advanced.get('exponent_bit_length', 0),
            advanced.get('modulus_bit_length', 0),

            float(advanced.get('curve25519_constant_detection', False)),
            advanced.get('ladder_step_count', 0),
            advanced.get('cswap_patterns', 0),
            advanced.get('projective_affine_ops_count', 0),
            advanced.get('mixed_coordinate_ratio', 0.0),

            advanced.get('quarterround_score', 0),
            float(advanced.get('mt19937_constants', False)),
            advanced.get('lcg_multiplier', 0),
            advanced.get('lcg_increment', 0),
            advanced.get('lcg_mod', 0),
            advanced.get('feedback_polynomial', 0),

            advanced.get('gf256_mul_ratio', 0.0),
            advanced.get('bitwise_mix_operations', 0),
            advanced.get('num_large_tables', 0),
            advanced.get('table_entropy_score', 0.0),
            float(advanced.get('tbox_detected', False)),

            advanced.get('stack_frame_size', 0),
            advanced.get('call_in_degree', 0),
            advanced.get('call_out_degree', 0),
            advanced.get('string_refs_count', 0),
            advanced.get('data_refs_count', 0),
            advanced.get('rodata_refs_count', 0),
            advanced.get('string_density', 0.0),
            advanced.get('pagerank_score', 0.0),
            advanced.get('betweenness_centrality', 0.0),
        ])

        # Entropy metrics
        entropy_metrics = func.get('entropy_metrics', {})
        features.extend([
            entropy_metrics.get('opcode_entropy', 0.0),
            entropy_metrics.get('operand_entropy', 0.0),
            entropy_metrics.get('control_flow_entropy', 0.0),
        ])

        # Crypto signatures
        crypto_sigs = func.get('crypto_signatures', {})
        features.extend([
            float(crypto_sigs.get('has_aes_key_schedule', False)),
            float(crypto_sigs.get('has_sha_init', False)),
            float(crypto_sigs.get('has_rsa_modexp', False)),
            float(crypto_sigs.get('has_ecc_point_ops', False)),
            crypto_sigs.get('constant_pool_score', 0.0),
        ])

        return features

    def _fit_scalers(self):
        """Fit feature scalers on the entire dataset."""
        if not self.graphs:
            return

        # Collect all features
        all_node_features = []
        all_edge_features = []
        all_graph_features = []

        for graph in self.graphs:
            all_node_features.append(graph['node_features'])
            if graph['edge_features'].shape[0] > 0:
                all_edge_features.append(graph['edge_features'])
            all_graph_features.append(graph['graph_features'])

        # Fit scalers
        all_node_features = np.vstack(all_node_features)
        all_graph_features = np.vstack(all_graph_features)

        self.node_scaler.fit(all_node_features)
        self.graph_scaler.fit(all_graph_features)

        if all_edge_features:
            all_edge_features = np.vstack(all_edge_features)
            self.edge_scaler.fit(all_edge_features)

    def __len__(self):
        return len(self.graphs)

    def __getitem__(self, idx):
        """Get a single graph sample."""
        graph = self.graphs[idx]
        label = self.labels[idx]

        # Scale features
        node_features = self.node_scaler.transform(graph['node_features'])
        graph_features = self.graph_scaler.transform(graph['graph_features'].reshape(1, -1))[0]

        edge_features = graph['edge_features']
        if edge_features.shape[0] > 0:
            edge_features = self.edge_scaler.transform(edge_features)

        # Convert to PyTorch Geometric Data object
        data = Data(
            x=torch.FloatTensor(node_features),
            edge_index=torch.LongTensor(graph['edge_index']),
            edge_attr=torch.FloatTensor(edge_features),
            y=torch.LongTensor([label]),
            graph_features=torch.FloatTensor(graph_features)
        )

        return data


# ============================================================================
# PART 2: GNN MODEL ARCHITECTURES
# ============================================================================

class AddressAwareGNN(nn.Module):
    """
    Address-Aware Graph Neural Network for Crypto Detection.

    Architecture:
    1. Node embedding with address features
    2. Multiple graph convolution layers (GCN/GAT/SAGE)
    3. Edge-aware message passing
    4. Graph-level pooling
    5. MLP classifier with graph features
    """

    def __init__(
        self,
        num_node_features: int,
        num_edge_features: int,
        num_graph_features: int,
        num_classes: int,
        hidden_dim: int = 256,
        num_layers: int = 4,
        dropout: float = 0.3,
        conv_type: str = 'gat',  # 'gcn', 'gat', 'sage', 'gin'
        pooling: str = 'concat',  # 'mean', 'max', 'concat'
    ):
        super().__init__()

        self.num_layers = num_layers
        self.hidden_dim = hidden_dim
        self.conv_type = conv_type
        self.pooling = pooling

        # Input projection layers
        self.node_encoder = nn.Sequential(
            nn.Linear(num_node_features, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )

        self.edge_encoder = nn.Sequential(
            nn.Linear(num_edge_features, hidden_dim // 2),
            nn.ReLU()
        ) if num_edge_features > 0 else None

        # Graph convolution layers
        self.convs = nn.ModuleList()
        self.batch_norms = nn.ModuleList()

        for i in range(num_layers):
            in_dim = hidden_dim
            out_dim = hidden_dim

            if conv_type == 'gcn':
                conv = GCNConv(in_dim, out_dim)
            elif conv_type == 'gat':
                conv = GATConv(in_dim, out_dim // 8, heads=8, dropout=dropout)
            elif conv_type == 'sage':
                conv = SAGEConv(in_dim, out_dim)
            elif conv_type == 'gin':
                mlp = nn.Sequential(
                    nn.Linear(in_dim, out_dim),
                    nn.ReLU(),
                    nn.Linear(out_dim, out_dim)
                )
                conv = GINConv(mlp)
            else:
                raise ValueError(f"Unknown conv type: {conv_type}")

            self.convs.append(conv)
            self.batch_norms.append(BatchNorm(out_dim))

        # Pooling dimension
        if pooling == 'concat':
            pool_dim = hidden_dim * 3  # mean + max + sum
        else:
            pool_dim = hidden_dim

        # MLP classifier
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim + num_graph_features, hidden_dim * 2),
            nn.BatchNorm1d(hidden_dim * 2),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.BatchNorm1d(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),

            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, data):
        x, edge_index, edge_attr, batch = data.x, data.edge_index, data.edge_attr, data.batch
        graph_features = data.graph_features

        # Reshape graph_features to [num_graphs, num_features]
        # When batched, it's concatenated into 1D: [g1_feat1, g1_feat2, ..., g2_feat1, g2_feat2, ...]
        num_graphs = batch.max().item() + 1
        num_graph_features = graph_features.shape[0] // num_graphs
        graph_features = graph_features.view(num_graphs, num_graph_features)

        # Encode node features
        x = self.node_encoder(x)

        # Graph convolutions with residual connections
        for i, (conv, bn) in enumerate(zip(self.convs, self.batch_norms)):
            x_input = x
            x = conv(x, edge_index)
            x = bn(x)
            x = F.relu(x)

            # Residual connection (skip every 2 layers)
            if i > 0 and i % 2 == 0:
                x = x + x_input

        # Graph-level pooling
        if self.pooling == 'mean':
            x = global_mean_pool(x, batch)
        elif self.pooling == 'max':
            x = global_max_pool(x, batch)
        elif self.pooling == 'concat':
            x_mean = global_mean_pool(x, batch)
            x_max = global_max_pool(x, batch)
            x_sum = global_add_pool(x, batch)
            x = torch.cat([x_mean, x_max, x_sum], dim=1)

        # Concatenate with graph-level features
        x = torch.cat([x, graph_features], dim=1)

        # Classification
        x = self.classifier(x)

        return x


class HierarchicalGNN(nn.Module):
    """
    Hierarchical GNN with multiple attention mechanisms.

    This model uses:
    1. Node-level attention (GAT)
    2. Edge-level attention (custom)
    3. Graph-level attention pooling
    """

    def __init__(
        self,
        num_node_features: int,
        num_edge_features: int,
        num_graph_features: int,
        num_classes: int,
        hidden_dim: int = 256,
        num_layers: int = 3,
        dropout: float = 0.3,
    ):
        super().__init__()

        self.node_encoder = nn.Linear(num_node_features, hidden_dim)

        # Multi-head GAT layers
        self.gat_layers = nn.ModuleList([
            GATConv(hidden_dim, hidden_dim // 4, heads=4, dropout=dropout)
            for _ in range(num_layers)
        ])

        self.batch_norms = nn.ModuleList([
            BatchNorm(hidden_dim) for _ in range(num_layers)
        ])

        # Attention-based pooling
        self.attention_pool = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.Tanh(),
            nn.Linear(hidden_dim // 2, 1)
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim + num_graph_features, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        graph_features = data.graph_features

        # Reshape graph_features to [num_graphs, num_features]
        num_graphs = batch.max().item() + 1
        num_graph_features = graph_features.shape[0] // num_graphs
        graph_features = graph_features.view(num_graphs, num_graph_features)

        x = self.node_encoder(x)

        # GAT layers
        for gat, bn in zip(self.gat_layers, self.batch_norms):
            x = gat(x, edge_index)
            x = bn(x)
            x = F.elu(x)

        # Attention pooling
        attn_weights = self.attention_pool(x)
        attn_weights = torch.softmax(attn_weights, dim=0)

        # Weighted sum pooling
        x_pooled = global_add_pool(x * attn_weights, batch)

        # Combine with graph features
        x = torch.cat([x_pooled, graph_features], dim=1)

        return self.classifier(x)


# ============================================================================
# PART 3: TRAINING AND EVALUATION
# ============================================================================

class GNNTrainer:
    """
    Trainer class for GNN models with comprehensive logging and visualization.
    """

    def __init__(
        self,
        model: nn.Module,
        train_loader: DataLoader,
        val_loader: DataLoader,
        test_loader: DataLoader,
        label_encoder: LabelEncoder,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu',
        lr: float = 0.001,
        weight_decay: float = 1e-4,
    ):
        self.model = model.to(device)
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.test_loader = test_loader
        self.label_encoder = label_encoder
        self.device = device

        # Handle class imbalance with weighted loss
        self.criterion = nn.CrossEntropyLoss()

        # Optimizer with weight decay
        self.optimizer = torch.optim.AdamW(
            model.parameters(),
            lr=lr,
            weight_decay=weight_decay
        )

        # Learning rate scheduler
        self.scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            self.optimizer,
            mode='max',
            factor=0.5,
            patience=10
        )

        # Training history
        self.history = {
            'train_loss': [],
            'train_acc': [],
            'val_loss': [],
            'val_acc': [],
            'val_f1': [],
        }

    def train_epoch(self) -> Tuple[float, float]:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0

        for batch in tqdm(self.train_loader, desc="Training", leave=False):
            batch = batch.to(self.device)

            self.optimizer.zero_grad()

            out = self.model(batch)
            loss = self.criterion(out, batch.y.squeeze())

            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
            self.optimizer.step()

            total_loss += loss.item() * batch.num_graphs
            pred = out.argmax(dim=1)
            correct += (pred == batch.y.squeeze()).sum().item()
            total += batch.num_graphs

        return total_loss / total, correct / total

    @torch.no_grad()
    def evaluate(self, loader: DataLoader) -> Tuple[float, float, float, np.ndarray, np.ndarray]:
        """Evaluate on a dataset."""
        self.model.eval()
        total_loss = 0
        all_preds = []
        all_labels = []

        for batch in loader:
            batch = batch.to(self.device)

            out = self.model(batch)
            loss = self.criterion(out, batch.y.squeeze())

            total_loss += loss.item() * batch.num_graphs
            pred = out.argmax(dim=1)

            all_preds.extend(pred.cpu().numpy())
            all_labels.extend(batch.y.squeeze().cpu().numpy())

        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)

        acc = accuracy_score(all_labels, all_preds)
        f1 = f1_score(all_labels, all_preds, average='weighted')
        avg_loss = total_loss / len(all_labels)

        return avg_loss, acc, f1, all_preds, all_labels

    def train(self, num_epochs: int, save_dir: str = './models'):
        """
        Train the model for multiple epochs.

        Args:
            num_epochs: Number of training epochs
            save_dir: Directory to save model checkpoints
        """
        os.makedirs(save_dir, exist_ok=True)
        best_val_f1 = 0

        print(f"\nTraining on device: {self.device}")
        print(f"Number of parameters: {sum(p.numel() for p in self.model.parameters()):,}")

        for epoch in range(num_epochs):
            print(f"\nEpoch {epoch+1}/{num_epochs}")
            print("-" * 50)

            # Train
            train_loss, train_acc = self.train_epoch()

            # Validate
            val_loss, val_acc, val_f1, _, _ = self.evaluate(self.val_loader)

            # Update learning rate
            self.scheduler.step(val_f1)

            # Log metrics
            self.history['train_loss'].append(train_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_loss'].append(val_loss)
            self.history['val_acc'].append(val_acc)
            self.history['val_f1'].append(val_f1)

            print(f"Train Loss: {train_loss:.4f} | Train Acc: {train_acc:.4f}")
            print(f"Val Loss: {val_loss:.4f} | Val Acc: {val_acc:.4f} | Val F1: {val_f1:.4f}")

            # Save best model
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                torch.save({
                    'epoch': epoch,
                    'model_state_dict': self.model.state_dict(),
                    'optimizer_state_dict': self.optimizer.state_dict(),
                    'val_f1': val_f1,
                }, os.path.join(save_dir, 'best_model.pth'))
                print(f"✓ Saved best model (F1: {val_f1:.4f})")

        print(f"\n{'='*50}")
        print(f"Training completed! Best Val F1: {best_val_f1:.4f}")
        print(f"{'='*50}")

    def test(self) -> Dict:
        """Evaluate on test set and generate comprehensive metrics."""
        print("\n" + "="*50)
        print("TESTING ON HELD-OUT TEST SET")
        print("="*50)

        test_loss, test_acc, test_f1, preds, labels = self.evaluate(self.test_loader)

        print(f"\nTest Loss: {test_loss:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")
        print(f"Test F1 (weighted): {test_f1:.4f}")

        # Classification report
        print("\n" + "="*50)
        print("CLASSIFICATION REPORT")
        print("="*50)
        print(classification_report(
            labels, preds,
            target_names=self.label_encoder.classes_,
            digits=4
        ))

        # Confusion matrix
        cm = confusion_matrix(labels, preds)

        return {
            'test_loss': test_loss,
            'test_acc': test_acc,
            'test_f1': test_f1,
            'predictions': preds,
            'labels': labels,
            'confusion_matrix': cm,
        }

    def plot_training_history(self, save_path: str = './training_history.png'):
        """Plot training curves."""
        fig, axes = plt.subplots(1, 3, figsize=(18, 5))

        # Loss
        axes[0].plot(self.history['train_loss'], label='Train Loss', marker='o')
        axes[0].plot(self.history['val_loss'], label='Val Loss', marker='s')
        axes[0].set_xlabel('Epoch')
        axes[0].set_ylabel('Loss')
        axes[0].set_title('Training and Validation Loss')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)

        # Accuracy
        axes[1].plot(self.history['train_acc'], label='Train Acc', marker='o')
        axes[1].plot(self.history['val_acc'], label='Val Acc', marker='s')
        axes[1].set_xlabel('Epoch')
        axes[1].set_ylabel('Accuracy')
        axes[1].set_title('Training and Validation Accuracy')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)

        # F1 Score
        axes[2].plot(self.history['val_f1'], label='Val F1', marker='s', color='green')
        axes[2].set_xlabel('Epoch')
        axes[2].set_ylabel('F1 Score')
        axes[2].set_title('Validation F1 Score')
        axes[2].legend()
        axes[2].grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"\n✓ Saved training history plot: {save_path}")

    def plot_confusion_matrix(self, cm: np.ndarray, save_path: str = './confusion_matrix.png'):
        """Plot confusion matrix."""
        plt.figure(figsize=(12, 10))

        # Normalize confusion matrix
        cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

        sns.heatmap(
            cm_norm,
            annot=True,
            fmt='.2f',
            cmap='Blues',
            xticklabels=self.label_encoder.classes_,
            yticklabels=self.label_encoder.classes_,
            cbar_kws={'label': 'Normalized Count'}
        )

        plt.xlabel('Predicted Label', fontsize=12)
        plt.ylabel('True Label', fontsize=12)
        plt.title('Confusion Matrix (Normalized)', fontsize=14, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        plt.tight_layout()
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"✓ Saved confusion matrix: {save_path}")


# ============================================================================
# PART 4: INFERENCE PIPELINE
# ============================================================================

class CryptoDetectionPipeline:
    """
    End-to-end pipeline for cryptographic function detection.

    Takes a JSON file from Ghidra and outputs detected crypto functions.
    """

    def __init__(
        self,
        model_path: str,
        metadata_path: str,
        device: str = 'cuda' if torch.cuda.is_available() else 'cpu'
    ):
        """
        Initialize the detection pipeline.

        Args:
            model_path: Path to trained model checkpoint
            metadata_path: Path to metadata pickle (scalers, label encoder)
            device: Device to run inference on
        """
        self.device = device

        # Load metadata
        with open(metadata_path, 'rb') as f:
            metadata = pickle.load(f)

        self.label_encoder = metadata['label_encoder']
        self.node_scaler = metadata['node_scaler']
        self.edge_scaler = metadata['edge_scaler']
        self.graph_scaler = metadata['graph_scaler']
        self.model_config = metadata['model_config']

        # Load model
        self.model = self._build_model()
        checkpoint = torch.load(model_path, map_location=device)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.eval()

        print(f"✓ Loaded model from {model_path}")
        print(f"✓ Model trained on {len(self.label_encoder.classes_)} classes")

    def _build_model(self):
        """Rebuild model from config."""
        return AddressAwareGNN(**self.model_config).to(self.device)

    def process_json(self, json_path: str, output_path: Optional[str] = None) -> Dict:
        """
        Process a Ghidra JSON file and detect crypto functions.

        Args:
            json_path: Path to input JSON file
            output_path: Optional path to save output JSON

        Returns:
            Dictionary with detection results
        """
        print(f"\nProcessing: {json_path}")

        # Load JSON
        with open(json_path, 'r') as f:
            data = json.load(f)

        results = {
            'source_file': os.path.basename(json_path),
            'binary_info': data.get('binary', {}),
            'metadata': data.get('metadata', {}),
            'crypto_functions': [],
            'statistics': {
                'total_functions': len(data['functions']),
                'crypto_detected': 0,
                'non_crypto': 0,
                'by_algorithm': Counter()
            }
        }

        # Process each function
        for func in tqdm(data['functions'], desc="Detecting crypto"):
            try:
                prediction = self._predict_function(func, data.get('binary', {}))

                if prediction['algorithm'] != 'Non-Crypto':
                    results['crypto_functions'].append({
                        'address': func['address'],
                        'name': func.get('name', 'unknown'),
                        'algorithm': prediction['algorithm'],
                        'confidence': prediction['confidence'],
                        'probabilities': prediction['probabilities'],
                        'graph_stats': func.get('graph_level', {}),
                        'advanced_features': func.get('advanced_features', {})
                    })
                    results['statistics']['crypto_detected'] += 1
                    results['statistics']['by_algorithm'][prediction['algorithm']] += 1
                else:
                    results['statistics']['non_crypto'] += 1

            except Exception as e:
                print(f"Error processing function {func.get('address', 'unknown')}: {e}")
                continue

        # Sort by confidence
        results['crypto_functions'].sort(key=lambda x: x['confidence'], reverse=True)

        # Save output
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n✓ Saved results to: {output_path}")

        # Print summary
        self._print_summary(results)

        return results

    def _predict_function(self, func: Dict, binary_info: Dict) -> Dict:
        """
        Predict crypto algorithm for a single function.

        Args:
            func: Function dictionary from JSON
            binary_info: Binary metadata

        Returns:
            Dictionary with prediction results
        """
        # Convert function to graph
        dataset = GraphDataset([], self.label_encoder)
        dataset.node_scaler = self.node_scaler
        dataset.edge_scaler = self.edge_scaler
        dataset.graph_scaler = self.graph_scaler

        graph_data = dataset._function_to_graph(func, binary_info)

        if graph_data is None:
            return {
                'algorithm': 'Unknown',
                'confidence': 0.0,
                'probabilities': {}
            }

        # Create Data object
        node_features = self.node_scaler.transform(graph_data['node_features'])
        graph_features = self.graph_scaler.transform(
            graph_data['graph_features'].reshape(1, -1)
        )[0]

        edge_features = graph_data['edge_features']
        if edge_features.shape[0] > 0:
            edge_features = self.edge_scaler.transform(edge_features)

        data = Data(
            x=torch.FloatTensor(node_features),
            edge_index=torch.LongTensor(graph_data['edge_index']),
            edge_attr=torch.FloatTensor(edge_features),
            graph_features=torch.FloatTensor(graph_features),
            batch=torch.zeros(node_features.shape[0], dtype=torch.long)
        ).to(self.device)

        # Predict
        with torch.no_grad():
            out = self.model(data)
            probs = F.softmax(out, dim=1)[0]
            pred_idx = probs.argmax().item()
            confidence = probs[pred_idx].item()

        # Create probability dictionary
        prob_dict = {
            self.label_encoder.classes_[i]: float(probs[i])
            for i in range(len(self.label_encoder.classes_))
        }

        return {
            'algorithm': self.label_encoder.classes_[pred_idx],
            'confidence': confidence,
            'probabilities': prob_dict
        }

    def _print_summary(self, results: Dict):
        """Print detection summary."""
        print("\n" + "="*60)
        print("CRYPTO DETECTION SUMMARY")
        print("="*60)
        print(f"Total functions analyzed: {results['statistics']['total_functions']}")
        print(f"Crypto functions detected: {results['statistics']['crypto_detected']}")
        print(f"Non-crypto functions: {results['statistics']['non_crypto']}")

        if results['statistics']['by_algorithm']:
            print("\nDetected algorithms:")
            for algo, count in results['statistics']['by_algorithm'].most_common():
                print(f"  {algo}: {count}")

        print("\nTop 5 crypto functions by confidence:")
        for i, func in enumerate(results['crypto_functions'][:5], 1):
            print(f"  {i}. {func['address']} ({func['name']})")
            print(f"     Algorithm: {func['algorithm']} (confidence: {func['confidence']:.4f})")


# ============================================================================
# PART 5: MAIN EXECUTION
# ============================================================================

def collate_fn(batch):
    """Custom collate function for DataLoader."""
    return Batch.from_data_list(batch)


def main():
    """Main training and evaluation pipeline."""

    # Configuration
    CONFIG = {
        'data_dir': '/home/bhoomi/Desktop/compilerRepo/vestigo-data/ghidra_json',
        'output_dir': './gnn_outputs',
        'model_dir': './gnn_models',

        # Model hyperparameters
        'hidden_dim': 256,
        'num_layers': 4,
        'dropout': 0.3,
        'conv_type': 'gat',  # 'gcn', 'gat', 'sage', 'gin'
        'pooling': 'concat',

        # Training hyperparameters
        'batch_size': 32,
        'num_epochs': 100,
        'lr': 0.001,
        'weight_decay': 1e-4,

        # Data split
        'train_ratio': 0.7,
        'val_ratio': 0.15,
        'test_ratio': 0.15,
    }

    # Create output directories
    os.makedirs(CONFIG['output_dir'], exist_ok=True)
    os.makedirs(CONFIG['model_dir'], exist_ok=True)

    print("="*60)
    print("ADDRESS-AWARE GNN FOR CRYPTO DETECTION")
    print("="*60)

    # ========================================================================
    # STEP 1: Load and prepare data
    # ========================================================================
    print("\n[STEP 1] Loading and preprocessing data...")

    json_files = glob.glob(os.path.join(CONFIG['data_dir'], '*.json'))
    print(f"Found {len(json_files)} JSON files")

    # Split files into train/val/test
    train_files, test_files = train_test_split(
        json_files,
        test_size=CONFIG['test_ratio'],
        random_state=42
    )

    train_files, val_files = train_test_split(
        train_files,
        test_size=CONFIG['val_ratio'] / (CONFIG['train_ratio'] + CONFIG['val_ratio']),
        random_state=42
    )

    print(f"Train files: {len(train_files)}")
    print(f"Val files: {len(val_files)}")
    print(f"Test files: {len(test_files)}")

    # Load datasets
    train_dataset = GraphDataset(train_files)
    val_dataset = GraphDataset(val_files, train_dataset.label_encoder)
    val_dataset.node_scaler = train_dataset.node_scaler
    val_dataset.edge_scaler = train_dataset.edge_scaler
    val_dataset.graph_scaler = train_dataset.graph_scaler

    test_dataset = GraphDataset(test_files, train_dataset.label_encoder)
    test_dataset.node_scaler = train_dataset.node_scaler
    test_dataset.edge_scaler = train_dataset.edge_scaler
    test_dataset.graph_scaler = train_dataset.graph_scaler

    # Create data loaders
    train_loader = DataLoader(
        train_dataset,
        batch_size=CONFIG['batch_size'],
        shuffle=True,
        collate_fn=collate_fn,
        num_workers=0
    )

    val_loader = DataLoader(
        val_dataset,
        batch_size=CONFIG['batch_size'],
        shuffle=False,
        collate_fn=collate_fn,
        num_workers=0
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=CONFIG['batch_size'],
        shuffle=False,
        collate_fn=collate_fn,
        num_workers=0
    )

    # ========================================================================
    # STEP 2: Build model
    # ========================================================================
    print("\n[STEP 2] Building GNN model...")

    # Get feature dimensions from a sample
    sample = train_dataset[0]
    num_node_features = sample.x.shape[1]
    num_edge_features = sample.edge_attr.shape[1] if sample.edge_attr.numel() > 0 else 0
    num_graph_features = sample.graph_features.shape[0]
    num_classes = len(train_dataset.label_encoder.classes_)

    print(f"Node features: {num_node_features}")
    print(f"Edge features: {num_edge_features}")
    print(f"Graph features: {num_graph_features}")
    print(f"Number of classes: {num_classes}")
    print(f"Classes: {train_dataset.label_encoder.classes_}")

    model = AddressAwareGNN(
        num_node_features=num_node_features,
        num_edge_features=num_edge_features,
        num_graph_features=num_graph_features,
        num_classes=num_classes,
        hidden_dim=CONFIG['hidden_dim'],
        num_layers=CONFIG['num_layers'],
        dropout=CONFIG['dropout'],
        conv_type=CONFIG['conv_type'],
        pooling=CONFIG['pooling'],
    )

    print(f"Model architecture: {CONFIG['conv_type'].upper()}")
    print(f"Total parameters: {sum(p.numel() for p in model.parameters()):,}")

    # ========================================================================
    # STEP 3: Train model
    # ========================================================================
    print("\n[STEP 3] Training model...")

    trainer = GNNTrainer(
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        test_loader=test_loader,
        label_encoder=train_dataset.label_encoder,
        lr=CONFIG['lr'],
        weight_decay=CONFIG['weight_decay']
    )

    trainer.train(
        num_epochs=CONFIG['num_epochs'],
        save_dir=CONFIG['model_dir']
    )

    # ========================================================================
    # STEP 4: Visualize training
    # ========================================================================
    print("\n[STEP 4] Generating visualizations...")

    trainer.plot_training_history(
        save_path=os.path.join(CONFIG['output_dir'], 'training_history.png')
    )

    # ========================================================================
    # STEP 5: Test and evaluate
    # ========================================================================
    print("\n[STEP 5] Evaluating on test set...")

    # Load best model
    best_checkpoint = torch.load(
        os.path.join(CONFIG['model_dir'], 'best_model.pth'),
        map_location=trainer.device
    )
    trainer.model.load_state_dict(best_checkpoint['model_state_dict'])

    test_results = trainer.test()

    # Plot confusion matrix
    trainer.plot_confusion_matrix(
        test_results['confusion_matrix'],
        save_path=os.path.join(CONFIG['output_dir'], 'confusion_matrix.png')
    )

    # ========================================================================
    # STEP 6: Save metadata for inference
    # ========================================================================
    print("\n[STEP 6] Saving metadata for inference...")

    metadata = {
        'label_encoder': train_dataset.label_encoder,
        'node_scaler': train_dataset.node_scaler,
        'edge_scaler': train_dataset.edge_scaler,
        'graph_scaler': train_dataset.graph_scaler,
        'model_config': {
            'num_node_features': num_node_features,
            'num_edge_features': num_edge_features,
            'num_graph_features': num_graph_features,
            'num_classes': num_classes,
            'hidden_dim': CONFIG['hidden_dim'],
            'num_layers': CONFIG['num_layers'],
            'dropout': CONFIG['dropout'],
            'conv_type': CONFIG['conv_type'],
            'pooling': CONFIG['pooling'],
        }
    }

    metadata_path = os.path.join(CONFIG['model_dir'], 'metadata.pkl')
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)

    print(f"✓ Saved metadata to: {metadata_path}")

    # ========================================================================
    # STEP 7: Demo inference
    # ========================================================================
    print("\n[STEP 7] Running inference demo...")

    pipeline = CryptoDetectionPipeline(
        model_path=os.path.join(CONFIG['model_dir'], 'best_model.pth'),
        metadata_path=metadata_path
    )

    # Test on a sample file
    demo_file = test_files[0]
    output_path = os.path.join(CONFIG['output_dir'], 'detection_results.json')

    results = pipeline.process_json(demo_file, output_path)

    print("\n" + "="*60)
    print("PIPELINE COMPLETE!")
    print("="*60)
    print(f"\nOutputs saved to: {CONFIG['output_dir']}")
    print(f"Model saved to: {CONFIG['model_dir']}")
    print("\nTo run inference on new files:")
    print(f"  python new_gnn.py --inference --input <json_file> --output <output_file>")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Address-Aware GNN for Crypto Detection')
    parser.add_argument('--inference', action='store_true', help='Run inference mode')
    parser.add_argument('--input', type=str, help='Input JSON file for inference')
    parser.add_argument('--output', type=str, help='Output JSON file for inference results')
    parser.add_argument('--model', type=str, default='./ml/gnn_models/best_model.pth', help='Model path')
    parser.add_argument('--metadata', type=str, default='./ml/gnn_models/metadata.pkl', help='Metadata path')

    args = parser.parse_args()

    if args.inference:
        if not args.input:
            print("Error: --input required for inference mode")
            exit(1)

        pipeline = CryptoDetectionPipeline(
            model_path=args.model,
            metadata_path=args.metadata
        )

        output_path = args.output or args.input.replace('.json', '_detections.json')
        pipeline.process_json(args.input, output_path)
    else:
        main()
