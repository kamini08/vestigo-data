#!/usr/bin/env python3
"""
Quick test to verify edge feature dimensions are consistent.
Run this to ensure the fix works before training.
"""

import sys
import glob
sys.path.insert(0, '/home/bhoomi/Desktop/compilerRepo/vestigo-data/ml')

try:
    from new_gnn import GraphDataset
    import numpy as np

    print("="*60)
    print("Testing Edge Feature Dimensions")
    print("="*60)

    # Load a small sample of JSON files
    json_files = glob.glob('/home/bhoomi/Desktop/compilerRepo/vestigo-data/ml/trainginJsonFiles/*.json')

    if not json_files:
        print("❌ No JSON files found!")
        print("   Check the path: /home/bhoomi/Desktop/compilerRepo/vestigo-data/ml/trainginJsonFiles/")
        sys.exit(1)

    print(f"\nFound {len(json_files)} JSON files")
    print(f"Testing with first 10 files...\n")

    # Load dataset with a small sample
    test_files = json_files[:10]
    dataset = GraphDataset(test_files)

    print(f"✓ Dataset loaded: {len(dataset)} functions\n")

    # Check edge feature dimensions
    print("Checking edge feature dimensions:")
    print("-" * 60)

    edge_dims = set()
    graphs_with_edges = 0
    graphs_without_edges = 0

    for i, graph in enumerate(dataset.graphs[:20]):  # Check first 20
        edge_shape = graph['edge_features'].shape
        edge_dims.add(edge_shape[1])  # Track unique dimensions

        if edge_shape[0] > 0:
            graphs_with_edges += 1
            status = "✓ HAS EDGES"
        else:
            graphs_without_edges += 1
            status = "✓ NO EDGES"

        print(f"  Graph {i:2d}: shape {edge_shape} {status}")

        # Verify dimension is 13
        if edge_shape[1] != 13:
            print(f"    ❌ ERROR: Expected 13 dimensions, got {edge_shape[1]}")
            sys.exit(1)

    print("\n" + "="*60)
    print("RESULTS")
    print("="*60)
    print(f"  Graphs with edges: {graphs_with_edges}")
    print(f"  Graphs without edges: {graphs_without_edges}")
    print(f"  Unique edge dimensions: {edge_dims}")

    if len(edge_dims) == 1 and 13 in edge_dims:
        print("\n✅ SUCCESS: All edge features have correct dimension (13)")
        print("\nYou can now run the notebook without dimension mismatch errors!")
        print("  jupyter notebook new_gnn_complete.ipynb")
    else:
        print(f"\n❌ FAILURE: Inconsistent edge dimensions: {edge_dims}")
        print("   Expected only {13}")
        sys.exit(1)

except ImportError as e:
    print("="*60)
    print("⚠️  Dependencies not installed")
    print("="*60)
    print(f"\nError: {e}")
    print("\nPlease install dependencies:")
    print("  pip install numpy torch torch-geometric")
    sys.exit(1)

except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
