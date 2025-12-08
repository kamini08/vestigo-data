#!/bin/bash
# Quick Reference: Refactored Crypto Analysis System

cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║          REFACTORED CRYPTO ANALYSIS SYSTEM - QUICK REFERENCE         ║
╚══════════════════════════════════════════════════════════════════════╝

┌─────────────────────────────────────────────────────────────────────┐
│ BASIC USAGE                                                         │
└─────────────────────────────────────────────────────────────────────┘

  # Single binary analysis (pipeline mode)
  $ python3 verify_crypto_refactored.py binary.elf | \
      python3 analyze_crypto_telemetry.py

  # Save telemetry for later
  $ python3 verify_crypto_refactored.py binary.elf > telemetry.json
  $ python3 analyze_crypto_telemetry.py telemetry.json > report.json

  # View classification only
  $ python3 verify_crypto_refactored.py binary.elf | \
      python3 analyze_crypto_telemetry.py | \
      jq '.classification'

┌─────────────────────────────────────────────────────────────────────┐
│ BATCH PROCESSING                                                    │
└─────────────────────────────────────────────────────────────────────┘

  # Collect telemetry from all binaries
  $ for bin in dataset_binaries/*.elf; do
      python3 verify_crypto_refactored.py "$bin" > \
          "telemetry_$(basename $bin).json"
    done

  # Analyze all telemetry
  $ for tel in telemetry_*.json; do
      python3 analyze_crypto_telemetry.py "$tel" > "report_$tel"
    done

┌─────────────────────────────────────────────────────────────────────┐
│ INSPECT DATA                                                        │
└─────────────────────────────────────────────────────────────────────┘

  # View telemetry structure
  $ jq 'keys' telemetry.json

  # Check syscalls captured
  $ jq '.syscalls' telemetry.json

  # View basic block stats
  $ jq '.basic_blocks | length' telemetry.json

  # Check memory writes
  $ jq '.memory_writes | length' telemetry.json

  # View YARA detections
  $ jq '.static_analysis.yara.detected' telemetry.json

  # Check constants found
  $ jq '.static_analysis.constants | keys' telemetry.json

┌─────────────────────────────────────────────────────────────────────┐
│ ANALYZE RESULTS                                                     │
└─────────────────────────────────────────────────────────────────────┘

  # View full classification
  $ jq '.classification' report.json

  # Get verdict only
  $ jq -r '.classification.verdict' report.json

  # Get confidence score
  $ jq -r '.classification.confidence' report.json

  # View evidence
  $ jq '.classification.evidence' report.json

  # Get recommendations
  $ jq '.classification.recommendations' report.json

┌─────────────────────────────────────────────────────────────────────┐
│ ADVANCED USAGE                                                      │
└─────────────────────────────────────────────────────────────────────┘

  # Combine multiple telemetry files
  $ jq -s '.' telemetry_*.json > combined_telemetry.json

  # Extract crypto loops only
  $ jq '.basic_blocks[] | select(.execution_count >= 3)' telemetry.json

  # Find high-entropy memory writes
  $ jq '.memory_writes[] | select(.entropy > 7.5)' telemetry.json

  # List all syscall types captured
  $ jq '[.syscalls | keys[]] | unique' telemetry.json

┌─────────────────────────────────────────────────────────────────────┐
│ DEBUGGING                                                           │
└─────────────────────────────────────────────────────────────────────┘

  # Check for errors in telemetry
  $ jq '.execution.error_message' telemetry.json

  # Validate JSON
  $ jq '.' telemetry.json > /dev/null && echo "Valid JSON" || echo "Invalid"

  # Check execution success
  $ jq -r '.execution.success' telemetry.json

  # View metadata
  $ jq '.metadata' telemetry.json

┌─────────────────────────────────────────────────────────────────────┐
│ KEY DIFFERENCES FROM OLD SCRIPT                                    │
└─────────────────────────────────────────────────────────────────────┘

  OLD: python3 verify_crypto.py binary.elf
       → Mixed text output with reports and verdicts

  NEW: python3 verify_crypto_refactored.py binary.elf
       → Pure JSON telemetry (no interpretation)

       python3 analyze_crypto_telemetry.py telemetry.json
       → Structured JSON report with classification

┌─────────────────────────────────────────────────────────────────────┐
│ TELEMETRY STRUCTURE                                                 │
└─────────────────────────────────────────────────────────────────────┘

  telemetry.json:
  {
    "metadata": {...},           // Binary info, timestamp, arch
    "static_analysis": {
      "yara": {...},             // YARA detections
      "constants": {...}         // Crypto constants found
    },
    "syscalls": {
      "getrandom": [...],        // Key generation calls
      "read_random": [...],      // /dev/urandom reads
      "socket": [...],           // Network activity
      "mmap": [...]              // Memory mappings
    },
    "execution": {...},          // Success status, errors
    "basic_blocks": [...],       // Instruction profiling
    "memory_writes": [...],      // Entropy analysis
    "crypto_regions": [...]      // Constant locations
  }

┌─────────────────────────────────────────────────────────────────────┐
│ REPORT STRUCTURE                                                    │
└─────────────────────────────────────────────────────────────────────┘

  report.json:
  {
    "metadata": {...},
    "syscall_analysis": {
      "random_generation": {...},
      "network_activity": {...}
    },
    "execution_analysis": {
      "crypto_loops": [...],
      "crypto_intensity": 0.15
    },
    "memory_analysis": {...},
    "classification": {
      "verdict": "STANDARD: AES",
      "confidence": "HIGH",
      "score": 75,
      "evidence": {...},
      "recommendations": [...]
    }
  }

┌─────────────────────────────────────────────────────────────────────┐
│ TESTING                                                             │
└─────────────────────────────────────────────────────────────────────┘

  # Run automated test
  $ ./test_refactored_system.sh [binary_path]

  # Test with default binary
  $ ./test_refactored_system.sh

┌─────────────────────────────────────────────────────────────────────┐
│ FILES                                                               │
└─────────────────────────────────────────────────────────────────────┘

  verify_crypto_refactored.py     - Telemetry collector
  analyze_crypto_telemetry.py     - LLM analyzer
  REFACTOR_README.md              - Full documentation
  REFACTOR_SUMMARY.md             - Change summary
  test_refactored_system.sh       - Test script
  quickref.sh                     - This file

┌─────────────────────────────────────────────────────────────────────┐
│ DOCUMENTATION                                                       │
└─────────────────────────────────────────────────────────────────────┘

  Full docs:     cat REFACTOR_README.md
  Summary:       cat REFACTOR_SUMMARY.md
  Quick ref:     ./quickref.sh

╔══════════════════════════════════════════════════════════════════════╗
║                       END OF QUICK REFERENCE                         ║
╚══════════════════════════════════════════════════════════════════════╝
EOF
