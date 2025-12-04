#!/usr/bin/env python3
"""
Batch Feature Extraction for Crypto Binary Dataset

Processes multiple crypto binaries to generate ML training dataset:
1. Runs feature_extractor.py on each binary
2. Analyzes crypto loops in resulting traces
3. Extracts ground truth labels from filenames
4. Generates consolidated training dataset

Usage:
    python3 batch_extract_features.py --dataset-dir /path/to/binaries --output-dir ./batch_results
    python3 batch_extract_features.py --parallel 4  # Use 4 parallel processes
"""

import os
import sys
import json
import subprocess
import argparse
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import concurrent.futures
from dataclasses import dataclass, asdict

@dataclass
class BinaryInfo:
    """Parsed information from binary filename"""
    filename: str
    algorithm: str
    architecture: str
    optimization: str
    version: str
    path: str
    
    @classmethod
    def from_filename(cls, filepath: str) -> Optional['BinaryInfo']:
        """
        Parse binary filename to extract metadata.
        Expected format: {ALGORITHM}_{arch}_{optimization}_{version}
        Example: AES128_arm_O0_v0
        """
        try:
            filename = Path(filepath).name
            parts = filename.split('_')
            
            if len(parts) < 4:
                print(f"⚠️  Warning: Unexpected filename format: {filename}")
                return None
            
            return cls(
                filename=filename,
                algorithm=parts[0],  # AES128, ECC, etc.
                architecture=parts[1],  # arm, x86, x64, etc.
                optimization=parts[2],  # O0, O1, O2, O3
                version=parts[3],  # v0, v1, etc.
                path=filepath
            )
        except Exception as e:
            print(f"❌ Error parsing {filepath}: {e}")
            return None


@dataclass
class ExtractionResult:
    """Result of processing one binary"""
    binary_info: BinaryInfo
    success: bool
    trace_path: Optional[str] = None
    loop_analysis_path: Optional[str] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    features_extracted: int = 0
    loops_found: int = 0


class BatchExtractor:
    """Manages batch feature extraction across multiple binaries"""
    
    def __init__(self, dataset_dir: str, output_dir: str, parallel: int = 1, timeout: int = 120):
        self.dataset_dir = Path(dataset_dir)
        self.output_dir = Path(output_dir)
        self.parallel = parallel
        self.timeout = timeout
        
        # Create output directories
        self.traces_dir = self.output_dir / "traces"
        self.loops_dir = self.output_dir / "loop_analysis"
        self.logs_dir = self.output_dir / "logs"
        
        for dir_path in [self.traces_dir, self.loops_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Results tracking
        self.results: List[ExtractionResult] = []
        self.start_time = time.time()
    
    def find_binaries(self) -> List[BinaryInfo]:
        """Discover all crypto binaries in dataset directory"""
        binaries = []
        
        if not self.dataset_dir.exists():
            raise FileNotFoundError(f"Dataset directory not found: {self.dataset_dir}")
        
        for filepath in sorted(self.dataset_dir.iterdir()):
            if filepath.is_file():
                binary_info = BinaryInfo.from_filename(str(filepath))
                if binary_info:
                    binaries.append(binary_info)
        
        return binaries
    
    def process_binary(self, binary_info: BinaryInfo) -> ExtractionResult:
        """Process a single binary: extract features and analyze loops"""
        start_time = time.time()
        result = ExtractionResult(binary_info=binary_info, success=False)
        
        try:
            # Step 1: Run feature extractor
            trace_filename = f"{binary_info.filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
            trace_path = self.traces_dir / trace_filename
            
            print(f"  📊 Extracting features from {binary_info.filename}...")
            
            env = os.environ.copy()
            env['QILING_OUTPUT_TRACE'] = str(trace_path)
            
            # Use absolute path to feature_extractor.py
            script_dir = Path(__file__).parent.absolute()
            feature_extractor_path = script_dir / "feature_extractor.py"
            
            cmd = [
                sys.executable,
                str(feature_extractor_path),
                binary_info.path
            ]
            
            proc = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=str(script_dir)
            )
            
            if proc.returncode != 0:
                result.error_message = f"Feature extraction failed: {proc.stderr[:200]}"
                return result
            
            if not trace_path.exists():
                result.error_message = "Trace file not created"
                return result
            
            # Count features extracted
            with open(trace_path) as f:
                result.features_extracted = sum(1 for _ in f)
            
            result.trace_path = str(trace_path)
            
            # Step 2: Analyze crypto loops
            print(f"  🔍 Analyzing crypto loops...")
            
            loop_output = self.loops_dir / f"{binary_info.filename}_loops.json"
            
            # Use absolute path to analyze_crypto_loops.py
            script_dir = Path(__file__).parent.absolute()
            loop_analyzer_path = script_dir / "analyze_crypto_loops.py"
            
            # Check if analyze_crypto_loops.py exists
            if not loop_analyzer_path.exists():
                print(f"  ⚠️  Warning: Loop analyzer not found at {loop_analyzer_path}, skipping...")
                result.loop_analysis_path = None
            else:
                cmd = [
                    sys.executable,
                    str(loop_analyzer_path),
                    str(trace_path)
                ]
                
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=str(script_dir)
                )
                
                # Parse loop analysis from stdout
                if "Found" in proc.stdout:
                    # Extract loop count from output like "Found 3 potential crypto loops"
                    import re
                    match = re.search(r'Found (\d+) potential crypto loops', proc.stdout)
                    if match:
                        result.loops_found = int(match.group(1))
                
                # Save loop analysis output
                with open(loop_output, 'w') as f:
                    json.dump({
                        'binary': binary_info.filename,
                        'stdout': proc.stdout,
                        'stderr': proc.stderr,
                        'loops_found': result.loops_found
                    }, f, indent=2)
                
                result.loop_analysis_path = str(loop_output)
            result.success = True
            
        except subprocess.TimeoutExpired:
            result.error_message = f"Timeout after {self.timeout}s"
        except Exception as e:
            result.error_message = f"Exception: {str(e)}"
        finally:
            result.execution_time = time.time() - start_time
        
        return result
    
    def process_all(self, binaries: List[BinaryInfo]) -> List[ExtractionResult]:
        """Process all binaries with optional parallel execution"""
        total = len(binaries)
        print(f"\n🚀 Processing {total} binaries (parallel={self.parallel})...")
        print(f"   Output directory: {self.output_dir}")
        print(f"   Timeout per binary: {self.timeout}s\n")
        
        if self.parallel > 1:
            # Parallel processing
            with concurrent.futures.ProcessPoolExecutor(max_workers=self.parallel) as executor:
                futures = {
                    executor.submit(self.process_binary, binary): binary 
                    for binary in binaries
                }
                
                for idx, future in enumerate(concurrent.futures.as_completed(futures), 1):
                    binary = futures[future]
                    result = future.result()
                    self.results.append(result)
                    self._print_progress(idx, total, result)
        else:
            # Sequential processing
            for idx, binary in enumerate(binaries, 1):
                result = self.process_binary(binary)
                self.results.append(result)
                self._print_progress(idx, total, result)
        
        return self.results
    
    def _print_progress(self, current: int, total: int, result: ExtractionResult):
        """Print progress for one binary"""
        status = "✅" if result.success else "❌"
        elapsed = time.time() - self.start_time
        avg_time = elapsed / current
        eta = avg_time * (total - current)
        
        info = result.binary_info
        print(f"{status} [{current}/{total}] {info.filename}")
        print(f"    Algorithm: {info.algorithm} | Arch: {info.architecture} | Opt: {info.optimization}")
        print(f"    Features: {result.features_extracted} | Loops: {result.loops_found} | Time: {result.execution_time:.1f}s")
        
        if not result.success:
            print(f"    ⚠️  Error: {result.error_message}")
        
        print(f"    Progress: {current/total*100:.1f}% | ETA: {eta/60:.1f} min\n")
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics and save results"""
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        # Group by algorithm
        by_algorithm = {}
        for result in successful:
            algo = result.binary_info.algorithm
            if algo not in by_algorithm:
                by_algorithm[algo] = []
            by_algorithm[algo].append(result)
        
        summary = {
            'total_binaries': len(self.results),
            'successful': len(successful),
            'failed': len(failed),
            'total_time': time.time() - self.start_time,
            'avg_time_per_binary': (time.time() - self.start_time) / len(self.results) if self.results else 0,
            'total_features_extracted': sum(r.features_extracted for r in successful),
            'total_loops_found': sum(r.loops_found for r in successful),
            'by_algorithm': {
                algo: {
                    'count': len(results),
                    'avg_features': sum(r.features_extracted for r in results) / len(results),
                    'avg_loops': sum(r.loops_found for r in results) / len(results)
                }
                for algo, results in by_algorithm.items()
            },
            'failed_binaries': [
                {
                    'filename': r.binary_info.filename,
                    'error': r.error_message
                }
                for r in failed
            ]
        }
        
        # Save detailed results
        results_file = self.output_dir / "batch_results.json"
        with open(results_file, 'w') as f:
            json.dump({
                'summary': summary,
                'results': [self._result_to_dict(r) for r in self.results]
            }, f, indent=2)
        
        # Save training dataset metadata
        dataset_file = self.output_dir / "training_dataset.json"
        with open(dataset_file, 'w') as f:
            json.dump({
                'traces': [
                    {
                        'trace_path': r.trace_path,
                        'loop_analysis_path': r.loop_analysis_path,
                        'label': {
                            'algorithm': r.binary_info.algorithm,
                            'architecture': r.binary_info.architecture,
                            'optimization': r.binary_info.optimization,
                            'version': r.binary_info.version
                        },
                        'features_count': r.features_extracted,
                        'loops_count': r.loops_found
                    }
                    for r in successful
                ]
            }, f, indent=2)
        
        return summary
    
    def _result_to_dict(self, result: ExtractionResult) -> Dict:
        """Convert result to JSON-serializable dict"""
        return {
            'binary': asdict(result.binary_info),
            'success': result.success,
            'trace_path': result.trace_path,
            'loop_analysis_path': result.loop_analysis_path,
            'error_message': result.error_message,
            'execution_time': result.execution_time,
            'features_extracted': result.features_extracted,
            'loops_found': result.loops_found
        }
    
    def print_summary(self, summary: Dict):
        """Print human-readable summary"""
        print("\n" + "="*70)
        print("📊 BATCH EXTRACTION SUMMARY")
        print("="*70)
        print(f"Total binaries: {summary['total_binaries']}")
        print(f"✅ Successful:   {summary['successful']}")
        print(f"❌ Failed:       {summary['failed']}")
        print(f"⏱️  Total time:   {summary['total_time']/60:.1f} minutes")
        print(f"⏱️  Avg per binary: {summary['avg_time_per_binary']:.1f} seconds")
        print(f"📊 Total features: {summary['total_features_extracted']}")
        print(f"🔍 Total loops:    {summary['total_loops_found']}")
        print()
        print("By Algorithm:")
        for algo, stats in summary['by_algorithm'].items():
            print(f"  {algo}:")
            print(f"    Count: {stats['count']}")
            print(f"    Avg features: {stats['avg_features']:.0f}")
            print(f"    Avg loops: {stats['avg_loops']:.1f}")
        print()
        
        if summary['failed_binaries']:
            print("Failed binaries:")
            for failed in summary['failed_binaries'][:10]:  # Show first 10
                print(f"  ❌ {failed['filename']}: {failed['error']}")
            if len(summary['failed_binaries']) > 10:
                print(f"  ... and {len(summary['failed_binaries']) - 10} more")
        
        print()
        print(f"📁 Results saved to: {self.output_dir}")
        print(f"   - batch_results.json (detailed results)")
        print(f"   - training_dataset.json (ML-ready dataset)")
        print(f"   - traces/ (feature extraction outputs)")
        print(f"   - loop_analysis/ (crypto loop analysis)")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description="Batch feature extraction for crypto binary dataset"
    )
    parser.add_argument(
        '--dataset-dir',
        default='/home/prajwal/Documents/LSTM-dataset/dataset',
        help='Directory containing crypto binaries'
    )
    parser.add_argument(
        '--output-dir',
        default='./batch_results',
        help='Output directory for results'
    )
    parser.add_argument(
        '--parallel',
        type=int,
        default=1,
        help='Number of parallel processes (default: 1)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Timeout per binary in seconds (default: 120)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        help='Process only first N binaries (for testing)'
    )
    
    args = parser.parse_args()
    
    # Create batch extractor
    extractor = BatchExtractor(
        dataset_dir=args.dataset_dir,
        output_dir=args.output_dir,
        parallel=args.parallel,
        timeout=args.timeout
    )
    
    # Find binaries
    print(f"🔍 Scanning dataset directory: {args.dataset_dir}")
    binaries = extractor.find_binaries()
    
    if not binaries:
        print("❌ No binaries found!")
        return 1
    
    print(f"✅ Found {len(binaries)} binaries")
    
    # Show algorithm distribution
    algo_counts = {}
    for binary in binaries:
        algo_counts[binary.algorithm] = algo_counts.get(binary.algorithm, 0) + 1
    
    print("\nAlgorithm distribution:")
    for algo, count in sorted(algo_counts.items()):
        print(f"  {algo}: {count} binaries")
    
    # Apply limit if specified
    if args.limit:
        binaries = binaries[:args.limit]
        print(f"\n⚠️  Limiting to first {args.limit} binaries for testing")
    
    # Process all binaries
    results = extractor.process_all(binaries)
    
    # Generate and print summary
    summary = extractor.generate_summary()
    extractor.print_summary(summary)
    
    return 0 if summary['failed'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
