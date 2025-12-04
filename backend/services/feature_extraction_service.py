"""
Feature Extraction Service for Vestigo Backend (Clean Version)
Handles real Ghidra analysis and feature extraction for binary files
"""

import os
import sys
import subprocess
import json
import tempfile
from typing import Dict, Any, List, Optional
from pathlib import Path
import time

from config.logging_config import logger

# Add lib directory to path for vestigo_features import
current_dir = Path(__file__).parent
project_root = current_dir.parent
lib_path = project_root / "lib"
if str(lib_path) not in sys.path:
    sys.path.append(str(lib_path))

try:
    from vestigo_features import FeatureExtractor, save_features_json
    VESTIGO_FEATURES_AVAILABLE = True
    logger.info("vestigo_features library loaded successfully")
except ImportError as e:
    logger.warning(f"vestigo_features library not available: {e}")
    VESTIGO_FEATURES_AVAILABLE = False

class FeatureExtractionService:
    """Service for extracting features from binary files using Ghidra"""
    
    def __init__(self):
        # Path to Ghidra and scripts
        self.ghidra_scripts_dir = Path(__file__).parent.parent.parent / "ghidra_scripts"
        self.extract_features_script = self.ghidra_scripts_dir / "extract_features.py"
        
        # Ghidra installation path (customize based on your setup)
        self.ghidra_path = os.environ.get("GHIDRA_INSTALL_DIR", "/opt/ghidra")
        self.ghidra_headless = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
        
        # Initialize standalone feature extractor
        if VESTIGO_FEATURES_AVAILABLE:
            self.feature_extractor = FeatureExtractor()
            logger.info("Standalone feature extractor initialized")
        else:
            self.feature_extractor = None
            logger.warning("Standalone feature extractor not available")
        
        logger.info(f"FeatureExtractionService initialized")
        logger.debug(f"Ghidra path: {self.ghidra_path}")
        logger.debug(f"Extract features script: {self.extract_features_script}")
    
    async def extract_features_from_archive_objects(self, job_id: str, extracted_objects: List[str], archive_name: str) -> Dict[str, Any]:
        """
        Extract features from multiple .o files extracted from a .a archive
        
        Args:
            job_id: Unique identifier for this analysis job
            extracted_objects: List of paths to extracted .o files
            archive_name: Name of the original .a archive file
            
        Returns:
            Dict containing combined features from all object files
        """
        logger.info(f"Starting archive object feature extraction - JobID: {job_id}, Archive: {archive_name}, Objects: {len(extracted_objects)}")
        
        if not extracted_objects:
            raise ValueError("No extracted objects provided for analysis")
        
        combined_results = {
            "job_id": job_id,
            "extraction_timestamp": time.time(),
            "status": "completed",
            "archive_name": archive_name,
            "object_files": [],
            "summary": {
                "total_object_files": len(extracted_objects),
                "total_functions": 0,
                "crypto_functions": 0,
                "non_crypto_functions": 0,
                "total_crypto_constants": 0,
                "average_entropy": 0.0
            },
            "analysis_tool": "ghidra_batch",
            "next_step": "classification_ready"
        }
        
        total_functions_all = 0
        total_crypto_all = 0
        total_constants_all = 0
        entropies_all = []
        
        try:
            # Process each .o file individually
            for obj_path in extracted_objects:
                logger.debug(f"Processing object file: {os.path.basename(obj_path)}")
                
                try:
                    # Extract features from individual object file
                    obj_features = await self.extract_features_from_binary(f"{job_id}_{os.path.basename(obj_path)}", obj_path)
                    
                    # Aggregate statistics
                    if "summary" in obj_features:
                        summary = obj_features["summary"]
                        total_functions_all += summary.get("total_functions", 0)
                        total_crypto_all += summary.get("crypto_functions", 0)
                        total_constants_all += summary.get("total_crypto_constants", 0)
                        
                        if summary.get("average_entropy", 0) > 0:
                            entropies_all.append(summary["average_entropy"])
                    
                    # Store individual object results
                    combined_results["object_files"].append({
                        "filename": os.path.basename(obj_path),
                        "path": obj_path,
                        "functions": obj_features.get("functions", []),
                        "summary": obj_features.get("summary", {}),
                        "metadata": obj_features.get("metadata", {})
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to extract features from {obj_path}: {str(e)}")
                    combined_results["object_files"].append({
                        "filename": os.path.basename(obj_path),
                        "path": obj_path,
                        "error": str(e),
                        "functions": [],
                        "summary": {},
                        "metadata": {}
                    })
            
            # Update combined summary
            combined_results["summary"]["total_functions"] = total_functions_all
            combined_results["summary"]["crypto_functions"] = total_crypto_all
            combined_results["summary"]["non_crypto_functions"] = total_functions_all - total_crypto_all
            combined_results["summary"]["total_crypto_constants"] = total_constants_all
            combined_results["summary"]["average_entropy"] = sum(entropies_all) / len(entropies_all) if entropies_all else 0.0
            
            logger.info(f"Archive object extraction completed - JobID: {job_id}, Archive: {archive_name}")
            logger.info(f"Total objects: {len(extracted_objects)}, Functions: {total_functions_all}, Crypto: {total_crypto_all}")
            
            return combined_results
            
        except Exception as e:
            logger.error(f"Archive object feature extraction failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
            raise

    async def extract_features_standalone(self, binary_path: str, job_id: str) -> Dict[str, Any]:
        """Extract features using standalone vestigo_features library (without Ghidra)"""
        logger.info(f"Starting standalone feature extraction - JobID: {job_id}, Binary: {binary_path}")
        
        if not VESTIGO_FEATURES_AVAILABLE:
            raise RuntimeError("vestigo_features library not available for standalone analysis")
        
        if not os.path.exists(binary_path):
            logger.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        try:
            # Basic binary analysis without Ghidra
            binary_data = self._prepare_basic_binary_data(binary_path)
            
            # Extract features using the modular library
            features = self.feature_extractor.extract_binary_features(binary_data)
            
            # Add metadata
            features["analysis_type"] = "standalone"
            features["job_id"] = job_id
            features["binary_path"] = binary_path
            
            logger.info(f"Standalone feature extraction completed - JobID: {job_id}")
            return features
            
        except Exception as e:
            logger.error(f"Standalone feature extraction failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
            raise
    
    def _prepare_basic_binary_data(self, binary_path: str) -> Dict[str, Any]:
        """Prepare basic binary data for standalone analysis"""
        binary_stat = os.stat(binary_path)
        binary_name = os.path.basename(binary_path)
        
        # Basic metadata (limited without Ghidra)
        metadata = {
            "binary_name": binary_name,
            "file_size": binary_stat.st_size,
            "architecture": "unknown",  # Would need more analysis
            "compiler": "unknown",
            "sections": {}
        }
        
        # For now, create empty functions list
        # In a real implementation, you might use other tools like objdump, readelf, etc.
        functions_data = []
        
        return {
            "functions": functions_data,
            "metadata": metadata
        }
    
    async def extract_features_from_binary(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        """
        Extract features from a binary file using Ghidra analysis
        
        Supports various binary formats:
        - ELF executables and object files (.o)
        - Archive files (.a) - will be processed by ingest module first to extract .o files
        - Binary files (.bin) - routed through appropriate analysis path
        
        Args:
            job_id: Unique identifier for this analysis job
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dict containing extracted features and analysis results
        """
        logger.info(f"Starting feature extraction - JobID: {job_id}, Binary: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        # Create temporary directory for Ghidra analysis
        with tempfile.TemporaryDirectory(prefix=f"ghidra_analysis_{job_id}_") as temp_dir:
            logger.debug(f"Created temporary Ghidra workspace: {temp_dir}")
            
            try:
                # Run Ghidra feature extraction
                features_result = await self._run_ghidra_analysis(
                    binary_path, temp_dir, job_id
                )
                
                # Process and structure the results
                processed_features = self._process_ghidra_output(features_result, job_id)
                
                logger.info(f"Feature extraction completed - JobID: {job_id}")
                return processed_features
                
            except Exception as e:
                logger.error(f"Feature extraction failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
                raise
    
    async def _run_ghidra_analysis(self, binary_path: str, workspace_dir: str, job_id: str) -> Dict[str, Any]:
        """Run Ghidra headless analysis"""
        logger.info(f"Running Ghidra analysis - JobID: {job_id}")
        
        # Check Ghidra availability
        if not os.path.exists(self.ghidra_headless):
            logger.error(f"Ghidra headless not found at: {self.ghidra_headless}")
            logger.info("Please set GHIDRA_INSTALL_DIR environment variable or install Ghidra")
            raise FileNotFoundError(f"Ghidra headless script not found: {self.ghidra_headless}")
        
        if not os.path.exists(self.extract_features_script):
            logger.error(f"Extract features script not found: {self.extract_features_script}")
            raise FileNotFoundError(f"Extract features script not found: {self.extract_features_script}")
        
        # Run real Ghidra analysis
        return await self._run_real_ghidra_analysis(binary_path, workspace_dir, job_id)
    
    async def _run_real_ghidra_analysis(self, binary_path: str, workspace_dir: str, job_id: str) -> Dict[str, Any]:
        """Run actual Ghidra analysis using the real extract_features.py script"""
        
        project_name = f"vestigo_analysis_{job_id}"
        binary_name = os.path.basename(binary_path)
        
        # The script saves to ghidra_json/BINARY_NAME_features.json by default
        # We need to pass the project root so the script can create the output directory
        project_root = str(Path(__file__).parent.parent.parent)  # vestigo-data root
        
        # Build Ghidra command - the script expects project root as argument
        ghidra_cmd = [
            self.ghidra_headless,
            workspace_dir,      # Ghidra project directory
            project_name,       # Project name
            "-import", binary_path,  # Import the binary
            "-postScript", str(self.extract_features_script), project_root,  # Run script with project root
            "-deleteProject"    # Clean up project after analysis
        ]
        
        logger.debug(f"Ghidra command: {' '.join(ghidra_cmd)}")
        
        try:
            # Run Ghidra analysis
            result = subprocess.run(
                ghidra_cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for complex binaries
                cwd=workspace_dir
            )
            
            if result.returncode != 0:
                logger.error(f"Ghidra analysis failed - JobID: {job_id}, Return code: {result.returncode}")
                logger.error(f"Ghidra stderr: {result.stderr}")
                logger.error(f"Ghidra stdout: {result.stdout}")
                raise RuntimeError(f"Ghidra analysis failed: {result.stderr}")
            
            logger.info(f"Ghidra execution completed - JobID: {job_id}")
            logger.debug(f"Ghidra output: {result.stdout}")
            
            # Calculate expected output file path - script saves to ghidra_json/BINARY_NAME_features.json
            expected_output = os.path.join(project_root, "ghidra_json", f"{binary_name}_features.json")
            
            # Read the output file
            if os.path.exists(expected_output):
                with open(expected_output, 'r') as f:
                    features = json.load(f)
                logger.info(f"Successfully loaded Ghidra features - JobID: {job_id}, Functions: {len(features.get('functions', []))}")
                return features
            else:
                logger.error(f"Expected Ghidra output file not found: {expected_output}")
                # List available files for debugging
                ghidra_json_dir = os.path.join(project_root, "ghidra_json")
                if os.path.exists(ghidra_json_dir):
                    available_files = os.listdir(ghidra_json_dir)
                    logger.debug(f"Available files in ghidra_json: {available_files}")
                raise FileNotFoundError(f"Ghidra analysis output not found: {expected_output}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra analysis timeout - JobID: {job_id}")
            raise TimeoutError("Ghidra analysis timed out")
        except Exception as e:
            logger.error(f"Ghidra execution error - JobID: {job_id}, Error: {str(e)}")
            raise
    
    def _process_ghidra_output(self, ghidra_result: Dict[str, Any], job_id: str) -> Dict[str, Any]:
        """Process and structure real Ghidra analysis output"""
        logger.debug(f"Processing Ghidra output - JobID: {job_id}")
        
        # Real Ghidra output format: {"binary": "name", "metadata": {...}, "functions": [...]}
        functions = ghidra_result.get("functions", [])
        metadata = ghidra_result.get("metadata", {})
        binary_name = ghidra_result.get("binary", "unknown")
        
        # Analyze function labels (crypto vs non-crypto)
        total_functions = len(functions)
        crypto_functions = len([f for f in functions if f.get("label", "Non-Crypto") != "Non-Crypto"])
        non_crypto_functions = total_functions - crypto_functions
        
        # Count crypto signatures found across all functions
        total_crypto_constants = sum(
            len(f.get("crypto_signatures", {}).get("detected_constants", []))
            for f in functions
        )
        
        # Extract entropy metrics
        avg_entropy = 0.0
        if functions:
            entropies = [f.get("entropy_metrics", {}).get("opcode_entropy", 0.0) for f in functions]
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        # Process advanced features
        advanced_features = {
            "total_tables_detected": metadata.get("total_tables_detected", 0),
            "text_size": metadata.get("text_size", 0),
            "rodata_size": metadata.get("rodata_size", 0),
            "data_size": metadata.get("data_size", 0)
        }
        
        processed_result = {
            "job_id": job_id,
            "extraction_timestamp": time.time(),
            "status": "completed",
            "binary_name": binary_name,
            "summary": {
                "total_functions": total_functions,
                "crypto_functions": crypto_functions,
                "non_crypto_functions": non_crypto_functions,
                "total_crypto_constants": total_crypto_constants,
                "average_entropy": round(avg_entropy, 4),
                "binary_sections": {
                    "text_size": advanced_features["text_size"],
                    "rodata_size": advanced_features["rodata_size"],
                    "data_size": advanced_features["data_size"]
                }
            },
            "functions": functions,  # Include full function analysis
            "metadata": metadata,
            "analysis_tool": "ghidra",
            "next_step": "classification_ready"
        }
        
        logger.info(f"Real Ghidra analysis processed - JobID: {job_id}, Binary: {binary_name}")
        logger.info(f"Functions: {total_functions}, Crypto: {crypto_functions}, "
                   f"Constants: {total_crypto_constants}, Avg Entropy: {avg_entropy:.4f}")
        
        return processed_result