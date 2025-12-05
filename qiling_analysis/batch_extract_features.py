#!/usr/bin/env python3
"""
Batch Feature Extraction for Crypto Binary Dataset

Processes multiple crypto binaries to generate ML training dataset:
1. Runs feature_extractor.py on each binary
2. Extracts windowed features using window_feature_extractor.py
3. Runs inference using crypto_inference_engine.py
4. Extracts ground truth labels from filenames
5. Generates consolidated training dataset with analysis

Usage:
    python3 batch_extract_features.py --dataset-dir /path/to/binaries --output-dir ./batch_results
    python3 batch_extract_features.py --parallel 4  # Use 4 parallel processes
    python3 batch_extract_features.py --full-pipeline  # Run complete pipeline (extraction + windowing + inference)
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

# Import our new components
PIPELINE_AVAILABLE = False
WindowFeatureExtractor = None
CryptoProtocolInferenceEngine = None
generate_enhanced_jsonl = None

def try_import_pipeline():
    """Try to import pipeline components (deferred until needed)"""
    global PIPELINE_AVAILABLE, WindowFeatureExtractor, CryptoProtocolInferenceEngine, generate_enhanced_jsonl
    try:
        from window_feature_extractor import WindowFeatureExtractor
        from crypto_inference_engine import CryptoProtocolInferenceEngine
        from enhanced_dataset_generator import generate_enhanced_jsonl
        PIPELINE_AVAILABLE = True
    except ImportError as e:
        PIPELINE_AVAILABLE = False
        print(f"⚠️  Warning: Pipeline import failed: {e}")
        print("   Full pipeline mode will not be available")
        print(f"   Missing module(s): Check if all files are present")

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
    windowed_features_path: Optional[str] = None
    enhanced_dataset_path: Optional[str] = None  # NEW: Path to enhanced multi-modal JSONL
    analysis_path: Optional[str] = None
    loop_analysis_path: Optional[str] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    features_extracted: int = 0
    windows_created: int = 0
    loops_found: int = 0
    crypto_windows_detected: int = 0


class BatchExtractor:
    """Manages batch feature extraction across multiple binaries"""
    
    def __init__(self, dataset_dir: str, output_dir: str, parallel: int = 1, 
                 timeout: int = 120, full_pipeline: bool = False):
        self.dataset_dir = Path(dataset_dir)
        self.output_dir = Path(output_dir)
        self.parallel = parallel
        self.timeout = timeout
        self.full_pipeline = full_pipeline
        
        # Create output directories
        self.traces_dir = self.output_dir / "traces"
        self.windowed_dir = self.output_dir / "windowed_features"
        self.analysis_dir = self.output_dir / "analysis_results"
        self.loops_dir = self.output_dir / "loop_analysis"
        self.logs_dir = self.output_dir / "logs"
        self.enhanced_dir = self.output_dir / "enhanced_datasets"  # NEW: For multi-modal JSONL
        
        for dir_path in [self.traces_dir, self.windowed_dir, self.analysis_dir, 
                         self.loops_dir, self.logs_dir, self.enhanced_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize pipeline components if full_pipeline enabled
        if self.full_pipeline:
            if not PIPELINE_AVAILABLE:
                # Try importing now
                try_import_pipeline()
            
            if PIPELINE_AVAILABLE:
                self.window_extractor = WindowFeatureExtractor(window_size=50, stride=25)
                self.inference_engine = CryptoProtocolInferenceEngine(mode='heuristic')
                print("✅ Full pipeline mode enabled (extraction → windowing → inference)")
            else:
                print("❌ Full pipeline requested but components not available!")
                print("   Falling back to extraction only")
                self.full_pipeline = False
        
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
        """Process a single binary: extract features, window, and analyze"""
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
            
            # Step 2: Full pipeline (windowing + inference) if enabled
            if self.full_pipeline and PIPELINE_AVAILABLE:
                print(f"  🪟 Creating windowed features...")
                
                # Load trace and create windows
                events = self.window_extractor.load_trace(str(trace_path))
                windows = self.window_extractor.create_windows(events)
                result.windows_created = len(windows)
                
                # Save windowed features
                windowed_path = self.windowed_dir / f"{binary_info.filename}_windowed.jsonl"
                self.window_extractor.save_windowed_dataset(windows, str(windowed_path))
                result.windowed_features_path = str(windowed_path)
                
                # NEW: Generate enhanced multi-modal training dataset
                print(f"  🎯 Generating enhanced training dataset...")
                enhanced_path = self.enhanced_dir / f"{binary_info.filename}_enhanced.jsonl"
                
                try:
                    # Convert windowed features to proper format for enhanced_dataset_generator
                    windowed_json_path = self.windowed_dir / f"{binary_info.filename}_windowed_dict.json"
                    
                    # Save windowed features as dict for enhanced generator
                    with open(windowed_json_path, 'w') as f:
                        json.dump({'windows': windows}, f)
                    
                    # Generate enhanced JSONL with structural patterns and runtime metrics
                    if generate_enhanced_jsonl:
                        generate_enhanced_jsonl(
                            trace_path=str(trace_path),
                            windowed_features_path=str(windowed_json_path),
                            output_path=str(enhanced_path),
                            label=binary_info.algorithm
                        )
                        result.enhanced_dataset_path = str(enhanced_path)  # NEW: Track enhanced dataset path
                        print(f"  ✅ Enhanced dataset created with structural patterns")
                except Exception as e:
                    print(f"  ⚠️  Warning: Enhanced dataset generation failed: {e}")
                
                print(f"  🧠 Running inference analysis...")
                
                # Run inference
                analysis_path = self.analysis_dir / f"{binary_info.filename}_analysis.jsonl"
                analysis_results = self.inference_engine.analyze_full_trace(
                    str(windowed_path),
                    str(analysis_path)
                )
                result.analysis_path = str(analysis_path)
                
                # Count crypto windows detected
                result.crypto_windows_detected = sum(
                    1 for r in analysis_results 
                    if r['analysis']['crypto_detection']['is_crypto']
                )
                
                print(f"  ✅ Detected crypto in {result.crypto_windows_detected}/{len(windows)} windows")
            
            # Step 3: Analyze crypto loops (legacy analysis)
            print(f"  🔍 Analyzing crypto loops...")
            
            loop_output = self.loops_dir / f"{binary_info.filename}_loops.json"
            
            # Use absolute path to analyze_crypto_loops.py
            loop_analyzer_path = script_dir / "analyze_crypto_loops.py"
            
            # Check if analyze_crypto_loops.py exists
            if not loop_analyzer_path.exists():
                print(f"  ⚠️  Warning: Loop analyzer not found, skipping...")
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
                    # Extract loop count from output
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
        
        if self.full_pipeline:
            print(f"    Windows: {result.windows_created} | Crypto detected: {result.crypto_windows_detected}")
        
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
        
        # Count enhanced datasets generated
        enhanced_datasets_count = sum(1 for r in successful if r.enhanced_dataset_path)
        
        summary = {
            'total_binaries': len(self.results),
            'successful': len(successful),
            'failed': len(failed),
            'total_time': time.time() - self.start_time,
            'avg_time_per_binary': (time.time() - self.start_time) / len(self.results) if self.results else 0,
            'total_features_extracted': sum(r.features_extracted for r in successful),
            'total_loops_found': sum(r.loops_found for r in successful),
            'total_windows_created': sum(r.windows_created for r in successful) if self.full_pipeline else 0,
            'total_crypto_windows_detected': sum(r.crypto_windows_detected for r in successful) if self.full_pipeline else 0,
            'enhanced_datasets_generated': enhanced_datasets_count,  # NEW: Count of enhanced multi-modal datasets
            'by_algorithm': {
                algo: {
                    'count': len(results),
                    'avg_features': sum(r.features_extracted for r in results) / len(results),
                    'avg_loops': sum(r.loops_found for r in results) / len(results),
                    'avg_windows': sum(r.windows_created for r in results) / len(results) if self.full_pipeline else 0,
                    'avg_crypto_windows': sum(r.crypto_windows_detected for r in results) / len(results) if self.full_pipeline else 0
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
                        'windowed_features_path': r.windowed_features_path,
                        'enhanced_dataset_path': r.enhanced_dataset_path,  # NEW: Include enhanced dataset path
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
            'windowed_features_path': result.windowed_features_path,
            'enhanced_dataset_path': result.enhanced_dataset_path,  # NEW: Include enhanced dataset path
            'analysis_path': result.analysis_path,
            'loop_analysis_path': result.loop_analysis_path,
            'error_message': result.error_message,
            'execution_time': result.execution_time,
            'features_extracted': result.features_extracted,
            'windows_created': result.windows_created,
            'loops_found': result.loops_found,
            'crypto_windows_detected': result.crypto_windows_detected
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
        
        if self.full_pipeline:
            print(f"🪟 Total windows:  {summary['total_windows_created']}")
            print(f"🔐 Crypto windows: {summary['total_crypto_windows_detected']}")
            print(f"📦 Enhanced datasets: {summary['enhanced_datasets_generated']}")  # NEW: Show enhanced dataset count
        
        print()
        print("By Algorithm:")
        for algo, stats in summary['by_algorithm'].items():
            print(f"  {algo}:")
            print(f"    Count: {stats['count']}")
            print(f"    Avg features: {stats['avg_features']:.0f}")
            print(f"    Avg loops: {stats['avg_loops']:.1f}")
            if self.full_pipeline:
                print(f"    Avg windows: {stats['avg_windows']:.0f}")
                print(f"    Avg crypto windows: {stats['avg_crypto_windows']:.0f}")
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
        if self.full_pipeline:
            print(f"   - windowed_features/ (windowed ML features)")
            print(f"   - enhanced_datasets/ (multi-modal JSONL datasets)")  # NEW: Show enhanced dataset directory
        if self.full_pipeline:
            print(f"   - windowed_features/ (ML-ready windowed features)")
            print(f"   - analysis_results/ (crypto inference results)")
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
    parser.add_argument(
        '--full-pipeline',
        action='store_true',
        help='Run complete pipeline: extraction → windowing → inference'
    )
    parser.add_argument(
        '--window-size',
        type=int,
        default=50,
        help='Window size for feature extraction (default: 50)'
    )
    parser.add_argument(
        '--stride',
        type=int,
        default=25,
        help='Stride for sliding window (default: 25)'
    )
    
    args = parser.parse_args()
    
    # Check if full pipeline is available
    if args.full_pipeline:
        # Try importing now that we're in the right directory
        try_import_pipeline()
        
        if not PIPELINE_AVAILABLE:
            print("❌ Full pipeline mode requires window_feature_extractor and crypto_inference_engine")
            print("   Please ensure these files exist in the current directory")
            return 1
    
    # Create batch extractor
    extractor = BatchExtractor(
        dataset_dir=args.dataset_dir,
        output_dir=args.output_dir,
        parallel=args.parallel,
        timeout=args.timeout,
        full_pipeline=args.full_pipeline
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
