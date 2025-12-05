#!/usr/bin/env python3
"""
Enhanced Cryptographic Function Analysis Pipeline with Ghidra JSON Support

Complete pipeline that:
1. Converts Ghidra JSON files to CSV with required features
2. Makes predictions for each function (row-wise)
3. Provides both function-wise and file-wise analysis in JSON format
4. Shows actual algorithm names and probabilities

Usage:
    python enhanced_crypto_pipeline.py --ghidra input.json --output analysis.json
    python enhanced_crypto_pipeline.py --csv input.csv --output analysis.json
    python enhanced_crypto_pipeline.py --features sample.json --output result.json
"""

import argparse
import json
import pandas as pd
import joblib
import sys
import os
import numpy as np
from pathlib import Path
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class GhidraFeatureExtractor:
    """Extract features from Ghidra JSON analysis files"""
    
    def __init__(self):
        """Initialize feature extractor with EXACT features from features.txt"""
        
        # EXACT features the model expects in EXACT order
        self.model_features = [
            'architecture', 'compiler', 'optimization', 'has_aes_sbox', 'rsa_bigint_detected',
            'has_aes_rcon', 'has_sha_constants', 'num_basic_blocks', 'num_edges', 'cyclomatic_complexity',
            'loop_count', 'loop_depth', 'branch_density', 'average_block_size', 'num_entry_exit_paths',
            'strongly_connected_components', 'instruction_count', 'immediate_entropy', 'bitwise_op_density',
            'crypto_constant_hits', 'branch_condition_complexity', 'add_ratio', 'logical_ratio',
            'load_store_ratio', 'xor_ratio', 'multiply_ratio', 'rotate_ratio', 'rodata_refs_count',
            'string_refs_count', 'stack_frame_size', 'bitwise_ops', 'crypto_like_ops', 'arithmetic_ops',
            'mem_ops_ratio', 'function_byte_entropy', 'opcode_entropy', 'cyclomatic_complexity_density',
            'unique_ngram_count', 'algorithm', 'num_conditional_edges', 'num_unconditional_edges',
            'num_loop_edges', 'avg_edge_branch_condition_complexplexity', 'source_file', 'table_lookup_presence',
            'original_label'
        ]
        
        self.categorical_features = ['architecture', 'compiler', 'optimization', 'algorithm', 'source_file', 'original_label']
        self.numerical_features = [f for f in self.model_features if f not in self.categorical_features]
        
        # For CSV output, include metadata columns
        self.all_features = ['function_name', 'function_address'] + self.model_features
    
    def extract_from_ghidra_json(self, json_file):
        """Extract features from Ghidra JSON file and convert to CSV format"""
        
        try:
            with open(json_file, 'r') as f:
                ghidra_data = json.load(f)
            
            # Store filename for inference
            self.current_filename = str(json_file)
            
            print(f"📁 Processing Ghidra JSON: {json_file}")
            
            # Handle different Ghidra JSON structures
            functions_data = []
            
            if isinstance(ghidra_data, list):
                # List of functions
                functions_data = ghidra_data
            elif isinstance(ghidra_data, dict):
                if 'functions' in ghidra_data:
                    functions_data = ghidra_data['functions']
                elif 'analysis' in ghidra_data and isinstance(ghidra_data['analysis'], list):
                    functions_data = ghidra_data['analysis']
                else:
                    # Single function analysis
                    functions_data = [ghidra_data]
            
            if not functions_data:
                raise ValueError("No function data found in JSON file")
            
            # Extract features for each function
            extracted_functions = []
            
            for i, func_data in enumerate(functions_data):
                print(f"Processing function {i+1}/{len(functions_data)}", end='\r')
                
                features = self._extract_function_features(func_data, i, ghidra_data)
                
                extracted_functions.append(features)
            
            print(f"\\n✓ Extracted features for {len(extracted_functions)} functions")
            
            # Convert to DataFrame
            df = pd.DataFrame(extracted_functions)
            
            # Ensure all required features are present with exact feature names
            for feature in self.all_features:
                if feature not in df.columns:
                    if feature in self.categorical_features:
                        df[feature] = self._get_default_categorical(feature, ghidra_data)
                    else:
                        df[feature] = 0
            
            # Only keep the EXACT features from features.txt (no duplicates)
            df = df[self.all_features]
            
            return df, extracted_functions
            
        except Exception as e:
            print(f"Error processing Ghidra JSON: {e}")
            return None, None
    
    def _extract_function_features(self, func_data, func_index, ghidra_data):
        """Extract EXACT features from Ghidra JSON with CORRECT values"""
        
        features = {}
        
        # ===== METADATA FOR CSV =====
        features['function_name'] = func_data.get('name', f'func_{func_index}')
        features['function_address'] = func_data.get('address', f'0x{func_index:08x}')
        
        # ===== MODEL CATEGORICAL FEATURES =====
        # Extract from metadata or infer from context
        features['architecture'] = self._extract_architecture(func_data, ghidra_data)
        features['compiler'] = self._extract_compiler(func_data, ghidra_data)
        features['optimization'] = self._extract_optimization(func_data, ghidra_data)
        features['algorithm'] = 'unknown'  # Will be predicted
        features['source_file'] = 'unknown'
        features['original_label'] = 'unknown'
        
        # ===== EXTRACT REAL VALUES FROM GHIDRA JSON STRUCTURE =====
        
        # Graph level features (these are already calculated in Ghidra)
        graph_level = func_data.get('graph_level', {})
        features['num_basic_blocks'] = graph_level.get('num_basic_blocks', 1)
        features['num_edges'] = graph_level.get('num_edges', 1)
        features['cyclomatic_complexity'] = graph_level.get('cyclomatic_complexity', 1)
        features['loop_count'] = graph_level.get('loop_count', 0)
        features['loop_depth'] = graph_level.get('loop_depth', 0)
        features['branch_density'] = graph_level.get('branch_density', 0.0)
        features['average_block_size'] = graph_level.get('average_block_size', 1.0)
        features['num_entry_exit_paths'] = graph_level.get('num_entry_exit_paths', 1)
        features['strongly_connected_components'] = graph_level.get('strongly_connected_components', 1)
        features['num_conditional_edges'] = graph_level.get('num_conditional_edges', 0)
        features['num_unconditional_edges'] = graph_level.get('num_unconditional_edges', 0)
        features['num_loop_edges'] = graph_level.get('num_loop_edges', 0)
        features['avg_edge_branch_condition_complexplexity'] = graph_level.get('avg_edge_branch_condition_complexity', 0.0)
        
        # Calculate total instruction count from basic blocks
        features['instruction_count'] = self._calculate_total_instruction_count(func_data)
        
        # Entropy metrics (already calculated in Ghidra)
        entropy_metrics = func_data.get('entropy_metrics', {})
        features['function_byte_entropy'] = entropy_metrics.get('function_byte_entropy', 0.0)
        features['opcode_entropy'] = entropy_metrics.get('opcode_entropy', 0.0)
        features['cyclomatic_complexity_density'] = entropy_metrics.get('cyclomatic_complexity_density', 0.0)
        
        # Extract crypto signatures (if available at top level)
        crypto_sigs = func_data.get('crypto_signatures', {})
        features['has_aes_sbox'] = crypto_sigs.get('has_aes_sbox', 0)
        features['rsa_bigint_detected'] = crypto_sigs.get('rsa_bigint_detected', 0)
        features['has_aes_rcon'] = crypto_sigs.get('has_aes_rcon', 0)
        features['has_sha_constants'] = crypto_sigs.get('has_sha_constants', 0)

        # Extract data references
        data_refs = func_data.get('data_references', {})
        features['rodata_refs_count'] = data_refs.get('rodata_refs_count', 0)
        features['string_refs_count'] = data_refs.get('string_refs_count', 0)
        features['stack_frame_size'] = data_refs.get('stack_frame_size', 64)

        # Extract crypto_constant_hits from node_level
        node_level = func_data.get('node_level', [])
        if node_level:
            # Sum crypto_constant_hits from all blocks
            total_crypto_hits = sum(block.get('crypto_constant_hits', 0) for block in node_level)
            features['crypto_constant_hits'] = total_crypto_hits

            # Check for table_lookup_presence in any block
            has_table = any(block.get('table_lookup_presence', False) for block in node_level)
            features['table_lookup_presence'] = 1 if has_table else 0
        else:
            features['crypto_constant_hits'] = 0
            features['table_lookup_presence'] = 0

        # Fallback to advanced_features if crypto_signatures not available
        advanced = func_data.get('advanced_features', {})
        if not crypto_sigs:
            features['has_aes_sbox'] = 1 if advanced.get('has_aes_sbox', False) else 0
            features['rsa_bigint_detected'] = 1 if advanced.get('bigint_op_count', 0) > 0 else 0
            features['has_aes_rcon'] = 1 if advanced.get('has_aes_rcon', False) else 0
            features['has_sha_constants'] = 1 if advanced.get('sha_init_constants_hits', 0) > 0 else 0

        if not data_refs:
            features['rodata_refs_count'] = advanced.get('rodata_refs_count', 0)
            features['string_refs_count'] = advanced.get('string_refs_count', 0)
            features['stack_frame_size'] = advanced.get('stack_frame_size', 64)

        if features['crypto_constant_hits'] == 0:
            features['crypto_constant_hits'] = advanced.get('aes_sbox_match_score', 0) + advanced.get('sha_k_table_hits', 0)

        if features['table_lookup_presence'] == 0:
            features['table_lookup_presence'] = 1 if advanced.get('num_large_tables', 0) > 0 else 0
        
        # Calculate remaining features from basic block data
        self._calculate_instruction_features(func_data, features)
        
        return features
    

    

    
    def _calculate_all_features_OLD_UNUSED(self, func_data, features, instructions):
        """Calculate ALL features exactly as listed in features.txt"""
        
        # Get basic values
        num_blocks = features['num_basic_blocks']
        num_edges = features['num_edges']  
        instruction_count = features['instruction_count']
        loop_count = features['loop_count']
        
        # ===== BASIC STRUCTURE FEATURES =====
        # branch_density
        features['branch_density'] = num_edges / instruction_count if instruction_count > 0 else 0
        
        # average_block_size
        features['average_block_size'] = instruction_count / num_blocks if num_blocks > 0 else 0
        
        # num_entry_exit_paths (estimate)
        features['num_entry_exit_paths'] = max(1, min(num_blocks, 2))
        
        # strongly_connected_components (estimate)
        features['strongly_connected_components'] = max(1, num_blocks // 3) if num_blocks > 0 else 1
        
        # ===== INSTRUCTION ANALYSIS =====
        if instructions:
            # Initialize all counters
            add_count = sub_count = mul_count = div_count = 0
            and_count = or_count = xor_count = not_count = shl_count = shr_count = 0
            mov_count = lea_count = push_count = pop_count = load_count = store_count = 0
            rol_count = ror_count = rcl_count = rcr_count = 0
            immediate_values = []
            opcodes = []
            bytes_data = []
            
            for instr in instructions:
                mnemonic = instr.get('mnemonic', '').lower()
                operands = instr.get('operands', [])
                opcodes.append(mnemonic)
                
                # Get instruction bytes for entropy
                if 'bytes' in instr:
                    bytes_data.extend(instr['bytes'])
                
                # Count arithmetic operations
                if 'add' in mnemonic: add_count += 1
                elif 'sub' in mnemonic: sub_count += 1
                elif any(x in mnemonic for x in ['mul', 'imul']): mul_count += 1
                elif any(x in mnemonic for x in ['div', 'idiv']): div_count += 1
                
                # Count logical operations
                elif 'and' in mnemonic: and_count += 1
                elif 'or' in mnemonic: or_count += 1
                elif 'xor' in mnemonic: xor_count += 1
                elif 'not' in mnemonic: not_count += 1
                elif any(x in mnemonic for x in ['shl', 'sal']): shl_count += 1
                elif any(x in mnemonic for x in ['shr', 'sar']): shr_count += 1
                
                # Count memory operations
                elif any(x in mnemonic for x in ['mov', 'movb', 'movw', 'movl', 'movq']): mov_count += 1
                elif 'lea' in mnemonic: lea_count += 1
                elif 'push' in mnemonic: push_count += 1
                elif 'pop' in mnemonic: pop_count += 1
                elif any(x in mnemonic for x in ['ldr', 'load']): load_count += 1
                elif any(x in mnemonic for x in ['str', 'store']): store_count += 1
                
                # Count rotate operations
                elif 'rol' in mnemonic: rol_count += 1
                elif 'ror' in mnemonic: ror_count += 1
                elif 'rcl' in mnemonic: rcl_count += 1
                elif 'rcr' in mnemonic: rcr_count += 1
                
                # Collect immediate values
                for operand in operands:
                    if isinstance(operand, dict):
                        if operand.get('type') == 'immediate' or 'immediate' in str(operand):
                            val = operand.get('value', 0)
                            immediate_values.append(val)
            
            total_instr = len(instructions)
            
            # ===== CALCULATE RATIOS =====
            features['add_ratio'] = (add_count + sub_count) / total_instr if total_instr > 0 else 0
            features['logical_ratio'] = (and_count + or_count + xor_count + not_count + shl_count + shr_count) / total_instr if total_instr > 0 else 0
            features['load_store_ratio'] = (mov_count + lea_count + push_count + pop_count + load_count + store_count) / total_instr if total_instr > 0 else 0
            features['xor_ratio'] = xor_count / total_instr if total_instr > 0 else 0
            features['multiply_ratio'] = mul_count / total_instr if total_instr > 0 else 0
            features['rotate_ratio'] = (rol_count + ror_count + rcl_count + rcr_count) / total_instr if total_instr > 0 else 0
            features['mem_ops_ratio'] = features['load_store_ratio']
            
            # ===== CALCULATE DENSITIES =====
            bitwise_total = and_count + or_count + xor_count + shl_count + shr_count + rol_count + ror_count + rcl_count + rcr_count
            features['bitwise_op_density'] = bitwise_total / total_instr if total_instr > 0 else 0
            
            # ===== CALCULATE COUNTS =====
            features['bitwise_ops'] = bitwise_total
            features['arithmetic_ops'] = add_count + sub_count + mul_count + div_count
            features['crypto_like_ops'] = bitwise_total + xor_count + (rol_count + ror_count + rcl_count + rcr_count) * 2
            
            # ===== CALCULATE ENTROPIES =====
            # Immediate entropy
            if immediate_values:
                unique_imm = len(set(immediate_values))
                total_imm = len(immediate_values)
                features['immediate_entropy'] = unique_imm / total_imm if total_imm > 0 else 0
            else:
                features['immediate_entropy'] = 0
                
            # Opcode entropy
            if opcodes:
                unique_opcodes = len(set(opcodes))
                total_opcodes = len(opcodes)
                features['opcode_entropy'] = unique_opcodes / total_opcodes if total_opcodes > 0 else 0
            else:
                features['opcode_entropy'] = 0
                
            # Function byte entropy
            if bytes_data:
                unique_bytes = len(set(bytes_data))
                total_bytes = len(bytes_data)
                features['function_byte_entropy'] = unique_bytes / total_bytes if total_bytes > 0 else 0
            else:
                features['function_byte_entropy'] = features['opcode_entropy']  # Fallback
                
            # Unique n-gram count (estimate from opcode patterns)
            ngrams = set()
            for i in range(len(opcodes) - 1):
                ngrams.add(f"{opcodes[i]}_{opcodes[i+1]}")
            features['unique_ngram_count'] = len(ngrams)
            
        else:
            # Default values when no instructions
            features.update({
                'add_ratio': 0, 'logical_ratio': 0, 'load_store_ratio': 0, 'xor_ratio': 0,
                'multiply_ratio': 0, 'rotate_ratio': 0, 'mem_ops_ratio': 0, 'bitwise_op_density': 0,
                'bitwise_ops': 0, 'arithmetic_ops': 0, 'crypto_like_ops': 0,
                'immediate_entropy': 0, 'opcode_entropy': 0, 'function_byte_entropy': 0,
                'unique_ngram_count': 0
            })
        
        # ===== CRYPTO INDICATORS =====
        crypto_analysis = func_data.get('crypto_analysis', {})
        features['has_aes_sbox'] = 1 if crypto_analysis.get('aes_sbox', False) else 0
        features['rsa_bigint_detected'] = 1 if crypto_analysis.get('rsa_constants', False) or crypto_analysis.get('big_integer_ops', False) else 0
        features['has_aes_rcon'] = 1 if crypto_analysis.get('aes_rcon', False) else 0
        features['has_sha_constants'] = 1 if crypto_analysis.get('sha_constants', False) else 0
        
        # ===== TABLE AND REFERENCE FEATURES =====
        features['table_lookup_presence'] = 1 if func_data.get('arrays') or func_data.get('tables') or func_data.get('lookup_tables') else 0
        
        # Count crypto constants
        crypto_hits = 0
        crypto_indicators = ['aes_sbox', 'aes_rcon', 'des_sbox', 'sha_constants', 'md5_constants', 'rsa_constants', 'ecc_constants']
        for indicator in crypto_indicators:
            if crypto_analysis.get(indicator, False):
                crypto_hits += 1
        features['crypto_constant_hits'] = crypto_hits
        
        features['rodata_refs_count'] = len(func_data.get('constants', []))
        features['string_refs_count'] = len(func_data.get('strings', []))
        features['stack_frame_size'] = func_data.get('stack_frame_size', func_data.get('frame_size', 64))
        
        # ===== COMPLEXITY FEATURES =====
        features['branch_condition_complexity'] = max(0, num_edges - num_blocks + 1) if num_blocks > 0 else 0
        features['cyclomatic_complexity_density'] = features['cyclomatic_complexity'] / instruction_count if instruction_count > 0 else 0
        
        # ===== EDGE ANALYSIS =====
        if num_edges > 0:
            # Estimate edge types
            features['num_conditional_edges'] = max(0, int(num_edges * 0.6))  # Estimate 60% conditional
            features['num_unconditional_edges'] = max(0, int(num_edges * 0.3))  # Estimate 30% unconditional
            features['num_loop_edges'] = min(loop_count, int(num_edges * 0.1))  # Estimate 10% loop edges
        else:
            features['num_conditional_edges'] = 0
            features['num_unconditional_edges'] = 0
            features['num_loop_edges'] = 0
        
        # Note: keeping the typo from the original training data
        features['avg_edge_branch_condition_complexplexity'] = features['branch_condition_complexity'] / num_edges if num_edges > 0 else 0
        
    def _calculate_total_instruction_count(self, func_data):
        """Calculate total instruction count from all basic blocks"""
        total_instructions = 0

        # First try node_level data
        node_level = func_data.get('node_level', [])
        if node_level:
            for block in node_level:
                total_instructions += block.get('instruction_count', 0)

        # Fall back to basic_blocks
        if total_instructions == 0:
            basic_blocks = func_data.get('basic_blocks', [])
            if basic_blocks:
                for block in basic_blocks:
                    total_instructions += block.get('instruction_count', 0)

        # Last fallback: use graph level average
        if total_instructions == 0:
            graph_level = func_data.get('graph_level', {})
            avg_block_size = graph_level.get('average_block_size', 10)
            num_blocks = graph_level.get('num_basic_blocks', 1)
            total_instructions = int(avg_block_size * num_blocks)

        return total_instructions
    
    def _calculate_instruction_features(self, func_data, features):
        """Calculate instruction-based features from node_level data (basic blocks)"""

        # Initialize counters
        total_add = total_logical = total_load_store = total_xor = 0
        total_multiply = total_rotate = total_bitwise = total_arithmetic = 0
        total_crypto_like = 0
        unique_opcodes = set()
        all_immediate_values = []
        unique_ngrams = set()

        # Get total instruction count
        total_instructions = features['instruction_count']

        # Process node_level data (basic blocks)
        node_level = func_data.get('node_level', [])

        if node_level:
            for block in node_level:
                # Get opcode histogram
                opcode_hist = block.get('opcode_histogram', {})

                for opcode, count in opcode_hist.items():
                    opcode_upper = opcode.upper()
                    opcode_lower = opcode.lower()
                    unique_opcodes.add(opcode_upper)

                    # Categorize operations based on opcode
                    # Arithmetic operations
                    if opcode_upper in ['ADD', 'SUB', 'ADDI', 'ADDIU', 'SUBI', 'SUBIU']:
                        total_add += count
                        total_arithmetic += count
                    elif opcode_upper in ['MUL', 'MULT', 'MULTU', 'DIV', 'DIVU', 'MULO', 'IMUL']:
                        total_multiply += count
                        total_arithmetic += count

                    # Logical/Bitwise operations
                    elif opcode_upper in ['AND', 'OR', 'XOR', 'NOT', 'NOR', 'ANDI', 'ORI', 'XORI']:
                        total_logical += count
                        total_bitwise += count
                        if 'XOR' in opcode_upper:
                            total_xor += count

                    # Shift and rotate operations
                    elif opcode_upper in ['SLL', 'SRL', 'SRA', 'SLLV', 'SRLV', 'SRAV',
                                         'ROL', 'ROR', 'RCL', 'RCR', 'ROTL', 'ROTR',
                                         'SHL', 'SHR', 'SAL', 'SAR']:
                        total_rotate += count
                        total_bitwise += count

                    # Load/Store operations
                    elif opcode_upper in ['LOAD', 'STORE', 'LW', 'SW', 'LB', 'SB', 'LH', 'SH',
                                         'LBU', 'LHU', 'LWU', 'LD', 'SD', 'MOV', 'MOVS', 'MOVB']:
                        total_load_store += count

                    # Carry operations (crypto relevant)
                    elif opcode_upper in ['CARRY', 'SCARRY', 'ADC', 'SBB']:
                        total_crypto_like += count

                # Extract immediate values from block
                block_immediates = block.get('immediates', [])
                if block_immediates:
                    all_immediate_values.extend(block_immediates)

                # Extract opcode ratios directly from block if available
                block_opcode_ratios = block.get('opcode_ratios', {})

            # Calculate crypto-like operations
            total_crypto_like = total_bitwise + total_xor + (total_rotate * 2)

        # If node_level didn't provide data, try op_category_counts
        op_counts = func_data.get('op_category_counts', {})
        if not node_level and op_counts:
            # Extract directly from op_category_counts
            total_bitwise = op_counts.get('bitwise_ops', 0)
            total_add = int(op_counts.get('add_ratio', 0) * total_instructions)
            total_logical = int(op_counts.get('logical_ratio', 0) * total_instructions)
            total_load_store = int(op_counts.get('load_store_ratio', 0) * total_instructions)
            total_xor = int(op_counts.get('xor_ratio', 0) * total_instructions)
            total_multiply = int(op_counts.get('multiply_ratio', 0) * total_instructions)
            total_rotate = int(op_counts.get('rotate_ratio', 0) * total_instructions)
            total_arithmetic = op_counts.get('arithmetic_ops', 0)
            total_crypto_like = op_counts.get('crypto_like_ops', 0)
        elif op_counts and total_instructions > 0:
            # Use op_category_counts to supplement/verify our calculations
            # Only override if we didn't calculate from node_level
            if total_bitwise == 0:
                total_bitwise = op_counts.get('bitwise_ops', 0)
            if total_arithmetic == 0:
                total_arithmetic = op_counts.get('arithmetic_ops', 0)
            if total_crypto_like == 0:
                total_crypto_like = op_counts.get('crypto_like_ops', 0)

        # Calculate ratios - prefer op_category_counts if available (already computed correctly)
        if op_counts and 'add_ratio' in op_counts:
            # Use pre-computed ratios from op_category_counts
            features['add_ratio'] = op_counts.get('add_ratio', 0)
            features['logical_ratio'] = op_counts.get('logical_ratio', 0)
            features['load_store_ratio'] = op_counts.get('load_store_ratio', 0)
            features['xor_ratio'] = op_counts.get('xor_ratio', 0)
            features['multiply_ratio'] = op_counts.get('multiply_ratio', 0)
            features['rotate_ratio'] = op_counts.get('rotate_ratio', 0)
            features['mem_ops_ratio'] = op_counts.get('mem_ops_ratio', 0)
        elif total_instructions > 0:
            # Calculate ratios from counts
            features['add_ratio'] = total_add / total_instructions
            features['logical_ratio'] = total_logical / total_instructions
            features['load_store_ratio'] = total_load_store / total_instructions
            features['xor_ratio'] = total_xor / total_instructions
            features['multiply_ratio'] = total_multiply / total_instructions
            features['rotate_ratio'] = total_rotate / total_instructions
            features['mem_ops_ratio'] = total_load_store / total_instructions
        else:
            features.update({
                'add_ratio': 0, 'logical_ratio': 0, 'load_store_ratio': 0, 'xor_ratio': 0,
                'multiply_ratio': 0, 'rotate_ratio': 0, 'mem_ops_ratio': 0
            })

        # Extract or calculate bitwise_op_density
        # First try from op_category_counts, then from node_level averages, then calculate
        if op_counts and 'bitwise_op_density' in op_counts:
            # This doesn't exist in op_category_counts, calculate it
            pass

        if total_instructions > 0 and 'bitwise_op_density' not in features:
            features['bitwise_op_density'] = total_bitwise / total_instructions
        elif 'bitwise_op_density' not in features:
            features['bitwise_op_density'] = 0

        # Operation counts
        features['bitwise_ops'] = total_bitwise
        features['arithmetic_ops'] = total_arithmetic
        features['crypto_like_ops'] = total_crypto_like

        # Extract immediate_entropy from node_level blocks (already computed in Ghidra)
        if node_level:
            # Average immediate entropy across all blocks
            entropies = [block.get('immediate_entropy', 0) for block in node_level if 'immediate_entropy' in block]
            if entropies:
                features['immediate_entropy'] = sum(entropies) / len(entropies)
            elif all_immediate_values:
                # Calculate from immediate values
                unique_imm = len(set(all_immediate_values))
                features['immediate_entropy'] = unique_imm / len(all_immediate_values) if all_immediate_values else 0
            else:
                features['immediate_entropy'] = 0
        elif all_immediate_values:
            # Calculate from immediate values
            unique_imm = len(set(all_immediate_values))
            features['immediate_entropy'] = unique_imm / len(all_immediate_values) if all_immediate_values else 0
        else:
            features['immediate_entropy'] = 0

        # Extract bitwise_op_density from node_level blocks (already computed in Ghidra)
        if node_level:
            # Average bitwise_op_density across all blocks
            densities = [block.get('bitwise_op_density', 0) for block in node_level if 'bitwise_op_density' in block]
            if densities:
                # Use weighted average by instruction count, or simple average
                features['bitwise_op_density'] = sum(densities) / len(densities)

        # Extract unique_ngram_count from instruction_sequence
        instruction_seq = func_data.get('instruction_sequence', {})
        if instruction_seq:
            features['unique_ngram_count'] = instruction_seq.get('unique_ngram_count', len(unique_opcodes))
        else:
            features['unique_ngram_count'] = len(unique_opcodes) if unique_opcodes else 0

        # Branch condition complexity (calculated from edges)
        features['branch_condition_complexity'] = max(0, features['num_edges'] - features['num_basic_blocks'])
    
    def _extract_architecture(self, func_data, ghidra_data):
        """Extract architecture from JSON data or filename"""
        # Try from metadata first
        if isinstance(ghidra_data, dict) and 'metadata' in ghidra_data:
            arch = ghidra_data['metadata'].get('architecture')
            if arch:
                return arch.lower()
        
        # Try from function data
        arch = func_data.get('architecture', func_data.get('arch'))
        if arch:
            return arch.lower()
        
        # Try to infer from filename patterns
        if hasattr(self, 'current_filename'):
            filename = self.current_filename.lower()
            if 'x86' in filename:
                return 'x86'
            elif 'arm' in filename:
                return 'arm'
            elif 'mips' in filename:
                return 'mips'
            elif 'aarch64' in filename:
                return 'aarch64'
        
        return 'unknown'
    
    def _extract_compiler(self, func_data, ghidra_data):
        """Extract compiler from JSON data or filename"""
        # Try from metadata first
        if isinstance(ghidra_data, dict) and 'metadata' in ghidra_data:
            compiler = ghidra_data['metadata'].get('compiler')
            if compiler:
                return compiler.lower()
        
        # Try from function data
        compiler = func_data.get('compiler')
        if compiler:
            return compiler.lower()
        
        # Try to infer from filename patterns
        if hasattr(self, 'current_filename'):
            filename = self.current_filename.lower()
            if 'gcc' in filename:
                return 'gcc'
            elif 'clang' in filename:
                return 'clang'
            elif 'msvc' in filename:
                return 'msvc'
        
        return 'gcc'  # Most common default
    
    def _extract_optimization(self, func_data, ghidra_data):
        """Extract optimization level from JSON data or filename"""
        # Try from metadata first
        if isinstance(ghidra_data, dict) and 'metadata' in ghidra_data:
            opt = ghidra_data['metadata'].get('optimization')
            if opt:
                return opt
        
        # Try from function data
        opt = func_data.get('optimization', func_data.get('opt_level'))
        if opt:
            return opt
        
        # Try to infer from filename patterns
        if hasattr(self, 'current_filename'):
            filename = self.current_filename.upper()
            if '_O0' in filename or '_O0.' in filename:
                return 'O0'
            elif '_O1' in filename or '_O1.' in filename:
                return 'O1'
            elif '_O2' in filename or '_O2.' in filename:
                return 'O2'
            elif '_O3' in filename or '_O3.' in filename:
                return 'O3'
            elif '_OS' in filename or '_Os' in filename:
                return 'Os'
        
        return 'O2'  # Most common default
    
    def _get_default_categorical(self, feature, ghidra_data):
        """Get default values for categorical features"""
        
        if feature == 'architecture':
            # Try to extract from file info or default to x86
            return ghidra_data.get('architecture', ghidra_data.get('arch', 'x86'))
        elif feature == 'compiler':
            return ghidra_data.get('compiler', 'gcc')
        elif feature == 'optimization':
            return ghidra_data.get('optimization', ghidra_data.get('opt_level', 'O2'))
        else:
            return 'unknown'

class EnhancedCryptoAnalysisPipeline:
    """Enhanced crypto analysis pipeline with Ghidra support"""
    
    def __init__(self, model_path=None, metadata_path=None):
        """Initialize the pipeline with saved model"""
        
        if model_path is None:
            # Try multiple possible locations for the model files
            possible_model_paths = [
                Path(__file__).parent / 'ml' / 'saved_models' / 'current_crypto_model.pkl',
                Path(__file__).parent / 'saved_models' / 'current_crypto_model.pkl',
                Path('ml/saved_models/current_crypto_model.pkl'),
                Path('saved_models/current_crypto_model.pkl')
            ]
            model_path = None
            for path in possible_model_paths:
                if path.exists():
                    model_path = path
                    break
        
        if metadata_path is None:
            # Try multiple possible locations for the metadata files
            possible_metadata_paths = [
                Path(__file__).parent / 'ml' / 'saved_models' / 'current_model_metadata.pkl',
                Path(__file__).parent / 'saved_models' / 'current_model_metadata.pkl',
                Path('ml/saved_models/current_model_metadata.pkl'),
                Path('saved_models/current_model_metadata.pkl')
            ]
            metadata_path = None
            for path in possible_metadata_paths:
                if path.exists():
                    metadata_path = path
                    break
        
        if not os.path.exists(model_path) or not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Model files not found. Please train a model first.")
        
        self.model = joblib.load(model_path)
        self.metadata = joblib.load(metadata_path)
        
        self.class_names = self.metadata['class_names']
        self.feature_columns = self.metadata['feature_columns']
        self.categorical_features = self.metadata['categorical_features']
        self.numerical_features = self.metadata['numerical_features']
        
        # Define crypto vs non-crypto classes
        # Exclude 'other', 'Non-Crypto', and any variants as non-crypto
        non_crypto_variants = ['other', 'Non-Crypto', 'non-crypto', 'OTHER']
        self.crypto_classes = [cls for cls in self.class_names if cls not in non_crypto_variants]
        self.non_crypto_classes = [cls for cls in self.class_names if cls in non_crypto_variants]
        
        # Initialize feature extractor
        self.feature_extractor = GhidraFeatureExtractor()
        
        print(f"✓ Model loaded: {self.metadata['model_name']}")
        print(f"✓ Classes: {self.class_names}")
        print(f"✓ Crypto classes: {len(self.crypto_classes)}")
        print(f"✓ Features: {len(self.feature_columns)}")
    
    def preprocess_features(self, features_dict):
        """Properly preprocess features handling categorical and numerical separately"""
        
        # Convert to DataFrame
        df = pd.DataFrame([features_dict])
        
        # Handle missing features - ensure we have all model features
        for col in self.feature_columns:
            if col not in df.columns:
                if col in ['architecture', 'compiler', 'optimization', 'algorithm', 'source_file', 'original_label']:
                    df[col] = 'unknown'  # Default for categorical
                else:
                    df[col] = 0  # Default for numerical
        
        # Ensure correct order - EXACT model feature order
        df = df[self.feature_columns]
        
        # Handle categorical columns properly
        for col in self.categorical_features:
            if col in df.columns:
                df[col] = df[col].astype(str).fillna('unknown')
        
        # Handle numerical columns
        for col in self.numerical_features:
            if col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        return df
    
    def analyze_crypto_indicators(self, features_dict):
        """Analyze crypto-specific indicators in the features"""
        
        crypto_indicators = {
            'has_crypto_constants': features_dict.get('has_crypto_constants', 0),
            'has_aes_sbox': features_dict.get('has_aes_sbox', 0),
            'has_aes_rcon': features_dict.get('has_aes_rcon', 0),
            'has_des_sbox': features_dict.get('has_des_sbox', 0),
            'has_sha_constants': features_dict.get('has_sha_constants', 0),
            'has_md5_constants': features_dict.get('has_md5_constants', 0),
            'has_rsa_constants': features_dict.get('has_rsa_constants', 0),
            'has_ecc_constants': features_dict.get('has_ecc_constants', 0),
            'rsa_bigint_detected': features_dict.get('rsa_bigint_detected', 0),
            'aes_round_detected': features_dict.get('aes_round_detected', 0),
            'des_round_detected': features_dict.get('des_round_detected', 0),
            'sha_round_detected': features_dict.get('sha_round_detected', 0),
            'md5_round_detected': features_dict.get('md5_round_detected', 0),
        }
        
        # Count positive indicators
        positive_indicators = sum(1 for v in crypto_indicators.values() if v > 0)
        
        # Calculate crypto strength based on indicators
        total_indicators = len(crypto_indicators)
        crypto_strength = positive_indicators / total_indicators if total_indicators > 0 else 0
        
        return {
            'indicators': crypto_indicators,
            'positive_indicators': positive_indicators,
            'total_indicators': total_indicators,
            'crypto_strength': crypto_strength
        }
    
    def determine_encryption_status(self, prediction, probabilities, crypto_analysis):
        """Determine if function is encrypted and provide analysis"""
        
        # Get total probability for crypto classes
        crypto_probability = sum(probabilities.get(cls, 0) for cls in self.crypto_classes)
        non_crypto_probability = sum(probabilities.get(cls, 0) for cls in self.non_crypto_classes)
        
        # Determine encryption status - exclude non-crypto variants
        non_crypto_variants = ['other', 'Non-Crypto', 'non-crypto', 'OTHER']
        is_encrypted = prediction not in non_crypto_variants and crypto_probability > non_crypto_probability
        
        # Calculate confidence based on multiple factors
        prediction_confidence = probabilities.get(prediction, 0)
        indicator_confidence = crypto_analysis['crypto_strength']
        
        # Combined confidence score
        overall_confidence = (prediction_confidence * 0.7 + indicator_confidence * 0.3)
        
        if is_encrypted:
            status = "ENCRYPTED"
            message = f"Function appears to implement cryptographic algorithm: {prediction}"
        elif crypto_analysis['positive_indicators'] > 0:
            status = "POSSIBLY_ENCRYPTED" 
            message = f"Some crypto indicators present but classified as: {prediction}"
        else:
            status = "NOT_ENCRYPTED"
            message = "Function does not appear to implement cryptographic algorithms"
        
        return {
            'is_encrypted': is_encrypted,
            'status': status,
            'message': message,
            'crypto_probability': float(crypto_probability),
            'non_crypto_probability': float(non_crypto_probability),
            'overall_confidence': float(overall_confidence)
        }
    
    def predict_and_analyze_function(self, features_dict, function_info=None):
        """Analyze a single function and return comprehensive results"""
        
        try:
            # Preprocess features
            df = self.preprocess_features(features_dict)
            
            # Make prediction
            prediction = self.model.predict(df)[0]
            probabilities = self.model.predict_proba(df)[0]
            
            # Convert prediction to actual class name
            predicted_algorithm = self.class_names[prediction] if isinstance(prediction, (int, np.integer)) else prediction
            
            # Create probability dictionary for all classes (with actual names)
            algorithm_probabilities = {}
            for i, class_name in enumerate(self.class_names):
                algorithm_probabilities[class_name] = float(probabilities[i])
            
            # Analyze crypto indicators
            crypto_analysis = self.analyze_crypto_indicators(features_dict)
            
            # Determine encryption status
            encryption_status = self.determine_encryption_status(predicted_algorithm, algorithm_probabilities, crypto_analysis)
            
            # Get top 5 predictions with detailed info
            sorted_probs = sorted(algorithm_probabilities.items(), key=lambda x: x[1], reverse=True)
            top_predictions = []
            
            for i, (algorithm, prob) in enumerate(sorted_probs[:5]):
                non_crypto_variants = ['other', 'Non-Crypto', 'non-crypto', 'OTHER']
                is_crypto = algorithm not in non_crypto_variants
                top_predictions.append({
                    'rank': i + 1,
                    'algorithm': algorithm,
                    'probability': float(prob),
                    'confidence_percent': float(prob * 100),
                    'is_crypto_algorithm': is_crypto,
                    'algorithm_type': self._get_algorithm_type(algorithm)
                })
            
            # Function analysis result
            function_analysis = {
                'function_info': function_info or {},
                'prediction': {
                    'predicted_algorithm': predicted_algorithm,
                    'confidence': float(max(probabilities)),
                    'confidence_percent': float(max(probabilities) * 100)
                },
                'encryption_analysis': encryption_status,
                'crypto_indicators': crypto_analysis,
                'algorithm_probabilities': {
                    'all_algorithms': algorithm_probabilities,
                    'crypto_algorithms': {k: v for k, v in algorithm_probabilities.items() if k in self.crypto_classes},
                    'non_crypto_algorithms': {k: v for k, v in algorithm_probabilities.items() if k in self.non_crypto_classes}
                },
                'top_predictions': top_predictions,
                'feature_summary': self._summarize_features(features_dict)
            }
            
            return function_analysis
            
        except Exception as e:
            return {
                'function_info': function_info or {},
                'error': str(e),
                'prediction': None,
                'encryption_analysis': {'status': 'ERROR', 'message': f'Analysis failed: {str(e)}'}
            }
    
    def _get_algorithm_type(self, algorithm):
        """Get the type/category of algorithm"""
        non_crypto_variants = ['other', 'Non-Crypto', 'non-crypto', 'OTHER']
        if algorithm in non_crypto_variants:
            return 'non-cryptographic'
        elif 'aes' in str(algorithm).lower():
            return 'symmetric-encryption'
        elif 'rsa' in str(algorithm).lower():
            return 'asymmetric-encryption'
        elif 'des' in str(algorithm).lower():
            return 'symmetric-encryption'
        elif 'ecc' in str(algorithm).lower():
            return 'asymmetric-encryption'
        elif any(hash_alg in str(algorithm).lower() for hash_alg in ['sha', 'md5']):
            return 'hash-function'
        elif 'prng' in str(algorithm).lower():
            return 'random-number-generation'
        else:
            return 'cryptographic'
    
    def _summarize_features(self, features_dict):
        """Create a summary of key features"""
        return {
            'architecture': features_dict.get('architecture', 'unknown'),
            'compiler': features_dict.get('compiler', 'unknown'),
            'optimization_level': features_dict.get('optimization_level', 'unknown'),
            'complexity': {
                'basic_blocks': int(features_dict.get('num_basic_blocks', 0)),
                'instructions': int(features_dict.get('num_instructions', 0)),
                'cyclomatic_complexity': int(features_dict.get('cyclomatic_complexity', 0))
            },
            'crypto_features': {
                'has_crypto_constants': bool(features_dict.get('has_crypto_constants', 0)),
                'detected_rounds': sum([
                    features_dict.get('aes_round_detected', 0),
                    features_dict.get('des_round_detected', 0),
                    features_dict.get('sha_round_detected', 0),
                    features_dict.get('md5_round_detected', 0)
                ])
            }
        }
    
    def process_ghidra_json(self, json_file, output_file):
        """Process Ghidra JSON file and generate comprehensive analysis"""
        
        try:
            # Extract features from Ghidra JSON
            df, function_data = self.feature_extractor.extract_from_ghidra_json(json_file)
            
            if df is None or function_data is None:
                print("Failed to extract features from Ghidra JSON")
                return None
            
            # Save intermediate CSV for reference
            csv_output = str(output_file).replace('.json', '_features.csv')
            df.to_csv(csv_output, index=False)
            print(f"Features saved to CSV: {csv_output}")
            
            # Analyze each function
            print(f"Analyzing {len(df)} functions...")
            function_analyses = []
            
            for idx, row in df.iterrows():
                print(f"Analyzing function {idx + 1}/{len(df)}", end='\\r')
                
                # Extract features that exist in the CSV and match the model features
                available_features = [f for f in self.feature_extractor.model_features if f in row.index]
                features = row[available_features].to_dict()
                
                # Add missing features with defaults
                for feature in self.feature_extractor.model_features:
                    if feature not in features:
                        if feature in self.feature_extractor.categorical_features:
                            features[feature] = 'unknown'
                        else:
                            features[feature] = 0
                
                # Function metadata
                function_info = {
                    'function_index': int(idx),
                    'function_name': row.get('function_name', f'func_{idx}'),
                    'function_address': row.get('function_address', f'addr_{idx}')
                }
                
                # Analyze function
                analysis = self.predict_and_analyze_function(features, function_info)
                function_analyses.append(analysis)
            
            print(f"\\n✓ All functions analyzed")
            
            # Generate file-wise analysis
            file_analysis = self._generate_file_analysis(function_analyses, json_file)
            
            # Comprehensive results
            results = {
                'analysis_metadata': {
                    'input_file': str(json_file),
                    'output_file': str(output_file),
                    'csv_features_file': csv_output,
                    'timestamp': datetime.now().isoformat(),
                    'total_functions': len(function_analyses),
                    'model_info': {
                        'model_name': self.metadata['model_name'],
                        'model_accuracy': self.metadata.get('model_accuracy', 'Unknown'),
                        'available_algorithms': list(self.class_names)
                    }
                },
                'file_analysis': file_analysis,
                'function_analyses': function_analyses
            }
            
            # Save results using JSON serializer
            results_str = json.dumps(results, default=self._json_serializer, indent=2)
            with open(output_file, 'w') as f:
                f.write(results_str)
            
            print(f"Comprehensive analysis saved to: {output_file}")
            self._print_analysis_summary(file_analysis)
            
            return results
            
        except Exception as e:
            print(f"Error processing Ghidra JSON: {e}")
            return None
    
    def process_csv_file(self, csv_file, output_file):
        """Process CSV file with enhanced analysis"""
        
        try:
            df = pd.read_csv(csv_file)
            print(f"Processing {len(df)} samples from {csv_file}")
            
            # Analyze each row as a function
            function_analyses = []
            
            for idx, row in df.iterrows():
                print(f"Processing sample {idx + 1}/{len(df)}", end='\\r')
                features = row.to_dict()
                
                # Function info from CSV
                function_info = {
                    'function_index': int(idx),
                    'function_name': features.get('function_name', f'function_{idx}'),
                    'function_address': features.get('function_address', f'addr_{idx}')
                }
                
                # Remove metadata from features for prediction
                prediction_features = {k: v for k, v in features.items() 
                                     if k in self.feature_extractor.all_features}
                
                # Analyze function
                analysis = self.predict_and_analyze_function(prediction_features, function_info)
                function_analyses.append(analysis)
            
            print(f"\\n✓ All samples analyzed")
            
            # Generate file-wise analysis
            file_analysis = self._generate_file_analysis(function_analyses, csv_file)
            
            # Results
            results = {
                'analysis_metadata': {
                    'input_file': str(csv_file),
                    'output_file': str(output_file),
                    'timestamp': datetime.now().isoformat(),
                    'total_functions': len(function_analyses),
                    'model_info': {
                        'model_name': self.metadata['model_name'],
                        'model_accuracy': self.metadata.get('model_accuracy', 'Unknown'),
                        'available_algorithms': list(self.class_names)
                    }
                },
                'file_analysis': file_analysis,
                'function_analyses': function_analyses
            }
            
            # Save results
            results_str = json.dumps(results, default=self._json_serializer, indent=2)
            with open(output_file, 'w') as f:
                f.write(results_str)
            
            print(f"Analysis saved to: {output_file}")
            self._print_analysis_summary(file_analysis)
            
            return results
            
        except Exception as e:
            print(f"Error processing CSV file: {e}")
            return None
    
    def _generate_file_analysis(self, function_analyses, input_file):
        """Generate overall file-wise analysis from function analyses"""
        
        successful_analyses = [f for f in function_analyses if 'error' not in f]
        
        if not successful_analyses:
            return {'error': 'No successful function analyses'}
        
        # Count encryption status
        encryption_counts = {}
        algorithm_counts = {}
        confidence_scores = []
        
        # Track highest crypto algorithm probabilities across all functions
        non_crypto_variants = ['other', 'Non-Crypto', 'non-crypto', 'OTHER']
        crypto_algorithm_probabilities = {}
        
        for func_analysis in successful_analyses:
            status = func_analysis['encryption_analysis']['status']
            encryption_counts[status] = encryption_counts.get(status, 0) + 1
            
            algorithm = func_analysis['prediction']['predicted_algorithm']
            algorithm_counts[algorithm] = algorithm_counts.get(algorithm, 0) + 1
            
            confidence_scores.append(func_analysis['prediction']['confidence'])
            
            # Collect crypto algorithm probabilities for each function
            if 'algorithm_probabilities' in func_analysis:
                all_probs = func_analysis['algorithm_probabilities'].get('all_algorithms', {})
                for algo, prob in all_probs.items():
                    if algo not in non_crypto_variants:
                        if algo not in crypto_algorithm_probabilities:
                            crypto_algorithm_probabilities[algo] = []
                        crypto_algorithm_probabilities[algo].append(prob)
        
        # Calculate statistics
        total_functions = len(successful_analyses)
        encrypted_count = encryption_counts.get('ENCRYPTED', 0)
        possibly_encrypted_count = encryption_counts.get('POSSIBLY_ENCRYPTED', 0)
        not_encrypted_count = encryption_counts.get('NOT_ENCRYPTED', 0)
        
        # Simplified algorithm classification logic:
        # 1. Sum up all algorithm predictions across all functions
        # 2. Rank them by total confidence
        # 3. If ALL functions are Non-Crypto → File is Non-Crypto
        # 4. If ANY function has crypto algorithm → File gets the highest-ranked crypto algorithm
        
        # Sum up all algorithm predictions with their confidence scores
        algorithm_totals = {}
        for func_analysis in successful_analyses:
            if 'algorithm_probabilities' in func_analysis:
                all_probs = func_analysis['algorithm_probabilities'].get('all_algorithms', {})
                for algo, prob in all_probs.items():
                    if algo not in algorithm_totals:
                        algorithm_totals[algo] = {
                            'total_confidence': 0.0,
                            'function_count': 0,
                            'max_confidence': 0.0,
                            'individual_confidences': []
                        }
                    algorithm_totals[algo]['total_confidence'] += prob
                    algorithm_totals[algo]['max_confidence'] = max(algorithm_totals[algo]['max_confidence'], prob)
                    algorithm_totals[algo]['individual_confidences'].append(prob)
                    
                    # Count function if this algorithm was the prediction
                    predicted_algorithm = func_analysis['prediction']['predicted_algorithm']
                    if algo == predicted_algorithm:
                        algorithm_totals[algo]['function_count'] += 1
        
        # Calculate average confidence and rank by total confidence
        algorithm_ranking = []
        crypto_algorithm_stats = {}
        
        for algo, data in algorithm_totals.items():
            avg_confidence = data['total_confidence'] / len(data['individual_confidences'])
            
            ranking_entry = {
                'algorithm': algo,
                'total_confidence': data['total_confidence'],
                'avg_confidence': avg_confidence,
                'max_confidence': data['max_confidence'],
                'function_count': data['function_count']
            }
            algorithm_ranking.append(ranking_entry)
            
            # Track crypto algorithm stats
            if algo not in non_crypto_variants:
                crypto_algorithm_stats[algo] = {
                    'avg_probability': avg_confidence,
                    'max_probability': data['max_confidence'],
                    'total_probability': data['total_confidence'],
                    'functions_with_probability': len([p for p in data['individual_confidences'] if p > 0.01])
                }
        
        # Sort by total confidence (sum of all predictions)
        algorithm_ranking.sort(key=lambda x: x['total_confidence'], reverse=True)
        
        # Separate crypto and non-crypto algorithms by counts
        crypto_algorithm_counts = {algo: count for algo, count in algorithm_counts.items() 
                                 if algo not in non_crypto_variants}
        non_crypto_algorithm_counts = {algo: count for algo, count in algorithm_counts.items() 
                                     if algo in non_crypto_variants}
        
        # Simple classification logic
        non_crypto_function_count = sum(non_crypto_algorithm_counts.values())
        crypto_function_count = sum(crypto_algorithm_counts.values())
        
        if non_crypto_function_count == total_functions:
            # ALL functions are Non-Crypto
            dominant_algorithm = 'Non-Crypto'
            crypto_percentage = 0.0
            sorted_algorithms = sorted(algorithm_counts.items(), key=lambda x: x[1], reverse=True)
        elif crypto_function_count > 0:
            # At least one function has a crypto algorithm - find the highest ranked crypto algorithm
            crypto_rankings = [r for r in algorithm_ranking if r['algorithm'] not in non_crypto_variants and r['function_count'] > 0]
            
            if crypto_rankings:
                dominant_algorithm = crypto_rankings[0]['algorithm']  # Highest ranked crypto algorithm
                crypto_percentage = (crypto_function_count / total_functions) * 100
                
                # Create sorted list prioritizing crypto algorithms by total confidence
                sorted_algorithms = []
                for rank in algorithm_ranking:
                    if rank['function_count'] > 0:  # Only include algorithms that actually classified functions
                        sorted_algorithms.append((rank['algorithm'], rank['function_count']))
            else:
                # Fallback - no crypto algorithms actually classified any functions
                dominant_algorithm = algorithm_ranking[0]['algorithm'] if algorithm_ranking else 'Non-Crypto'
                crypto_percentage = 0.0
                sorted_algorithms = sorted(algorithm_counts.items(), key=lambda x: x[1], reverse=True)
        else:
            # Fallback case
            dominant_algorithm = algorithm_ranking[0]['algorithm'] if algorithm_ranking else 'Non-Crypto'
            crypto_percentage = 0.0
            sorted_algorithms = sorted(algorithm_counts.items(), key=lambda x: x[1], reverse=True)
        
        if crypto_percentage > 70:
            file_status = "CRYPTO_HEAVY"
            file_message = "File contains predominantly cryptographic functions"
        elif crypto_percentage > 30:
            file_status = "MIXED_CRYPTO"
            file_message = "File contains some cryptographic functions"
        elif crypto_percentage > 0:
            file_status = "MINIMAL_CRYPTO"
            file_message = "File contains few cryptographic functions"
        else:
            file_status = "NO_CRYPTO"
            file_message = "File contains no detected cryptographic functions"
        
        return {
            'file_info': {
                'input_file': str(input_file),
                'total_functions': total_functions,
                'successful_analyses': len(successful_analyses),
                'failed_analyses': len(function_analyses) - len(successful_analyses)
            },
            'overall_assessment': {
                'file_status': file_status,
                'message': file_message,
                'crypto_percentage': float(crypto_percentage),
                'average_confidence': float(np.mean(confidence_scores)),
                'confidence_std': float(np.std(confidence_scores))
            },
            'encryption_distribution': {
                'encrypted_functions': int(encrypted_count),
                'possibly_encrypted_functions': int(possibly_encrypted_count),
                'not_encrypted_functions': int(not_encrypted_count),
                'encrypted_percentage': float((encrypted_count / total_functions) * 100),
                'crypto_detected_percentage': float(crypto_percentage)
            },
            'algorithm_distribution': {
                'counts': {str(algo): int(count) for algo, count in algorithm_counts.items()},
                'top_algorithms': [(str(algo), int(count)) for algo, count in sorted_algorithms[:5]],
                'dominant_algorithm': str(dominant_algorithm),
                'crypto_algorithm_counts': {str(algo): int(count) for algo, count in crypto_algorithm_counts.items()},
                'non_crypto_algorithm_counts': {str(algo): int(count) for algo, count in non_crypto_algorithm_counts.items()},
                'algorithm_diversity': len(algorithm_counts),
                'crypto_algorithm_diversity': len(crypto_algorithm_counts),
                'crypto_probability_analysis': {
                    str(algo): {
                        'avg_probability': float(stats['avg_probability']),
                        'max_probability': float(stats['max_probability']),
                        'functions_with_significant_probability': int(stats['functions_with_probability'])
                    } for algo, stats in crypto_algorithm_stats.items()
                },
                'algorithm_ranking': [
                    {
                        'algorithm': str(rank['algorithm']),
                        'total_confidence': float(rank['total_confidence']),
                        'avg_confidence': float(rank['avg_confidence']),
                        'max_confidence': float(rank['max_confidence']),
                        'function_count': int(rank['function_count'])
                    } for rank in algorithm_ranking
                ]
            },
            'confidence_statistics': {
                'mean_confidence': float(np.mean(confidence_scores)),
                'median_confidence': float(np.median(confidence_scores)),
                'min_confidence': float(np.min(confidence_scores)),
                'max_confidence': float(np.max(confidence_scores)),
                'std_confidence': float(np.std(confidence_scores))
            }
        }
    
    def _json_serializer(self, obj):
        """JSON serializer for numpy and pandas objects"""
        if isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif hasattr(obj, 'item'):  # numpy scalar
            return obj.item()
        elif pd.isna(obj):
            return None
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        else:
            return str(obj)  # fallback to string representation
    
    def _print_analysis_summary(self, file_analysis):
        """Print comprehensive analysis summary"""
        
        print("\\n" + "="*80)
        print("COMPREHENSIVE CRYPTOGRAPHIC ANALYSIS SUMMARY")
        print("="*80)
        
        file_info = file_analysis['file_info']
        assessment = file_analysis['overall_assessment']
        encryption = file_analysis['encryption_distribution']
        algorithms = file_analysis['algorithm_distribution']
        
        print(f"File: {file_info['input_file']}")
        print(f"Total Functions: {file_info['total_functions']}")
        print(f"Successful Analyses: {file_info['successful_analyses']}")
        
        print(f"\\n Overall Assessment:")
        print(f"  Status: {assessment['file_status']}")
        print(f"  {assessment['message']}")
        print(f"  Crypto Percentage: {assessment['crypto_percentage']:.1f}%")
        print(f"  Average Confidence: {assessment['average_confidence']:.1%}")
        
        print(f"\\n Encryption Distribution:")
        print(f"  Encrypted: {encryption['encrypted_functions']} ({encryption['encrypted_percentage']:.1f}%)")
        print(f"  Possibly Encrypted: {encryption['possibly_encrypted_functions']}")
        print(f"  Not Encrypted: {encryption['not_encrypted_functions']}")
        
        print(f"\\n Top Detected Algorithms:")
        for algorithm, count in algorithms['top_algorithms']:
            percentage = (count / file_info['total_functions']) * 100
            print(f"  {algorithm}: {count} functions ({percentage:.1f}%)")
        
        print(f"\\n Algorithm Ranking (by total confidence):")
        if 'algorithm_ranking' in algorithms:
            for i, rank in enumerate(algorithms['algorithm_ranking'][:5], 1):
                print(f"  {i}. {rank['algorithm']}: Total={rank['total_confidence']:.1f}, Avg={rank['avg_confidence']:.1f}%, Functions={rank['function_count']}")
        
        print(f"\\n Algorithm Diversity: {algorithms['algorithm_diversity']} different algorithms detected")
        print("="*80)

def main():
    parser = argparse.ArgumentParser(description="Enhanced Crypto Analysis Pipeline with Ghidra Support")
    parser.add_argument('--ghidra', help='Input Ghidra JSON file')
    parser.add_argument('--csv', help='Input CSV file with features')
    parser.add_argument('--features', help='Input JSON file with features')
    parser.add_argument('--output', '-o', required=True, help='Output JSON file for analysis')
    parser.add_argument('--model-path', help='Path to model file')
    parser.add_argument('--metadata-path', help='Path to metadata file')
    
    args = parser.parse_args()
    
    if not any([args.ghidra, args.csv, args.features]):
        parser.print_help()
        return
    
    try:
        # Initialize enhanced pipeline
        pipeline = EnhancedCryptoAnalysisPipeline(args.model_path, args.metadata_path)
        
        if args.ghidra:
            # Process Ghidra JSON file
            print(f" Processing Ghidra JSON: {args.ghidra}")
            results = pipeline.process_ghidra_json(args.ghidra, args.output)
            
        elif args.csv:
            # Process CSV file
            print(f" Processing CSV: {args.csv}")
            results = pipeline.process_csv_file(args.csv, args.output)
        
        elif args.features:
            # Process single JSON file
            print(f" Loading features from: {args.features}")
            with open(args.features, 'r') as f:
                features = json.load(f)
            
            # Analyze single function
            analysis = pipeline.predict_and_analyze_function(features)
            
            # Save result
            results = {
                'analysis_metadata': {
                    'input_file': args.features,
                    'timestamp': datetime.now().isoformat(),
                    'analysis_type': 'single_function',
                    'model_info': {
                        'model_name': pipeline.metadata['model_name'],
                        'available_algorithms': list(pipeline.class_names)
                    }
                },
                'function_analysis': analysis
            }
            
            results_str = json.dumps(results, default=pipeline._json_serializer, indent=2)
            with open(args.output, 'w') as f:
                f.write(results_str)
            
            print(f" Single function analysis saved to: {args.output}")
            
            # Print results
            if analysis['encryption_analysis']['is_encrypted']:
                print(f"\\n {analysis['encryption_analysis']['message']}")
                print(f"Algorithm: {analysis['prediction']['predicted_algorithm']}")
                print(f"Confidence: {analysis['prediction']['confidence_percent']:.1f}%")
                
                print("\\n Top Algorithm Probabilities:")
                for pred in analysis['top_predictions'][:3]:
                    print(f"  {pred['algorithm']}: {pred['confidence_percent']:.1f}%")
            else:
                print(f"\\n {analysis['encryption_analysis']['message']}")
    
    except Exception as e:
        print(f" Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()