#!/usr/bin/env python3
"""Test torch_scatter CUDA support"""

import torch
import torch_scatter

print(f"PyTorch version: {torch.__version__}")
print(f"CUDA available: {torch.cuda.is_available()}")
print(f"torch_scatter version: {torch_scatter.__version__}")

# Test on CPU
try:
    src = torch.randn(10, 5)
    index = torch.tensor([0, 0, 1, 1, 1, 2, 2, 2, 3, 3])
    result = torch_scatter.scatter_max(src, index, dim=0)
    print("✓ CPU scatter_max works")
except Exception as e:
    print(f"✗ CPU scatter_max failed: {e}")

# Test on CUDA
if torch.cuda.is_available():
    try:
        src_cuda = torch.randn(10, 5).cuda()
        index_cuda = torch.tensor([0, 0, 1, 1, 1, 2, 2, 2, 3, 3]).cuda()
        result_cuda = torch_scatter.scatter_max(src_cuda, index_cuda, dim=0)
        print("✓ CUDA scatter_max works")
    except Exception as e:
        print(f"✗ CUDA scatter_max failed: {e}")
        print("\nRecommendation: Use CPU mode by setting device='cpu' in trainer")
