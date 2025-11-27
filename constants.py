"""Configuration constants for classify_with_openai.py

Edit values here to change defaults used by the script.
"""
from pathlib import Path

# File/default paths (relative to repo root when running script)
DEFAULT_INPUT = 'aes128_arm_clang_Os.elf_features.json'
DEFAULT_RULES_DIR = 'ml/rules'
DEFAULT_FEATURES_CSV = 'features.csv'
DEFAULT_OUTPUT = 'classified_out.csv'

# LLM and batching defaults
DEFAULT_MODEL = 'gpt-4'
DEFAULT_BATCH_SIZE = 5
DEFAULT_MAX_TOKENS = 1500

# Retry/backoff behavior when hitting token limits
MAX_BATCH_RETRIES = 4
MIN_BATCH_SIZE = 1

# Logging format
LOG_FORMAT = '%(asctime)s %(levelname)s: %(message)s'
LOG_DATEFMT = '%Y-%m-%d %H:%M:%S'
