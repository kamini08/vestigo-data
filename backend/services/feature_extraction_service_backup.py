"""
Feature Extraction Service for Vestigo Backend
Handles Ghidra analysis and feature extraction for binary files
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
        self.extract_features_script = self.ghidra_scripts_dir / "extract_features_modular.py"
        
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
            # This is limited analysis based on file properties and basic parsing
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
        
        Args:
            job_id (str): Job identifier for tracking
            binary_path (str): Path to the binary file to analyze
            
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
    
    async def _run_mock_ghidra_analysis(self, binary_path: str, job_id: str) -> Dict[str, Any]:
        """Mock Ghidra analysis for development/testing"""
        logger.info(f"Running mock Ghidra analysis - JobID: {job_id}")
        
        # Simulate processing time
        await self._async_sleep(2)
        
        # Get basic file information
        file_size = os.path.getsize(binary_path)
        file_name = os.path.basename(binary_path)
        
        # Generate mock features based on file characteristics
        mock_features = {
            "metadata": {
                "file_name": file_name,
                "file_size": file_size,
                "analysis_timestamp": time.time(),
                "ghidra_version": "mock_11.0.3"
            },
            "crypto_constants": self._generate_mock_crypto_constants(),
            "function_analysis": self._generate_mock_function_analysis(file_name),
            "instruction_features": self._generate_mock_instruction_features(),
            "entropy_analysis": self._generate_mock_entropy_analysis(),
            "string_analysis": self._generate_mock_string_analysis(file_name)
        }
        
        logger.info(f"Mock Ghidra analysis completed - JobID: {job_id}")
        return mock_features
    
    def _generate_mock_crypto_constants(self) -> List[Dict[str, Any]]:
        """Generate mock cryptographic constants detection"""
        return [
            {
                "constant_type": "AES_SBOX",
                "address": "0x401000",
                "confidence": 0.95,
                "matches": 4
            },
            {
                "constant_type": "SHA256_K", 
                "address": "0x402000",
                "confidence": 0.87,
                "matches": 6
            }
        ]
    
    def _generate_mock_function_analysis(self, file_name: str) -> List[Dict[str, Any]]:
        """Generate mock function analysis results"""
        functions = []
        
        # Generate different crypto functions based on filename
        if "aes" in file_name.lower() or "encrypt" in file_name.lower():
            functions.extend([
                {
                    "name": "aes_encrypt",
                    "address": "0x401500", 
                    "size": 256,
                    "crypto_score": 0.92,
                    "classification": "crypto"
                },
                {
                    "name": "key_expansion",
                    "address": "0x401600",
                    "size": 180,
                    "crypto_score": 0.88,
                    "classification": "crypto"
                }
            ])
        
        if "sha" in file_name.lower() or "hash" in file_name.lower():
            functions.append({
                "name": "sha256_transform",
                "address": "0x402500",
                "size": 320,
                "crypto_score": 0.94,
                "classification": "crypto" 
            })
        
        # Add some non-crypto functions
        functions.extend([
            {
                "name": "main",
                "address": "0x400000",
                "size": 64,
                "crypto_score": 0.1,
                "classification": "non_crypto"
            },
            {
                "name": "memcpy",
                "address": "0x403000", 
                "size": 48,
                "crypto_score": 0.05,
                "classification": "non_crypto"
            }
        ])
        
        return functions
    
    def _generate_mock_instruction_features(self) -> Dict[str, Any]:
        """Generate mock instruction-level features"""
        return {
            "total_instructions": 1248,
            "arithmetic_ops": 342,
            "logical_ops": 156,
            "memory_ops": 234,
            "control_flow_ops": 98,
            "crypto_indicators": {
                "xor_operations": 45,
                "shift_operations": 67,
                "rotation_operations": 23
            }
        }
    
    def _generate_mock_entropy_analysis(self) -> Dict[str, Any]:
        """Generate mock entropy analysis"""
        return {
            "file_entropy": 7.2,
            "section_entropies": {
                ".text": 6.8,
                ".data": 4.2,
                ".rodata": 5.1
            },
            "high_entropy_regions": [
                {
                    "address": "0x401000",
                    "size": 1024, 
                    "entropy": 7.8
                }
            ]
        }
    
    def _generate_mock_string_analysis(self, file_name: str) -> Dict[str, Any]:
        """Generate mock string analysis"""
        crypto_strings = []
        
        if "openssl" in file_name.lower():
            crypto_strings.extend(["OpenSSL", "AES", "RSA", "SHA"])
        if "mbedtls" in file_name.lower():
            crypto_strings.extend(["mbedTLS", "AES_ENCRYPT", "SHA256"])
        
        return {
            "total_strings": 45,
            "crypto_related_strings": crypto_strings,
            "base64_patterns": 3,
            "hex_patterns": 12
        }
    
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
    
    async def _async_sleep(self, seconds: float):
        """Async sleep helper"""
        import asyncio
        await asyncio.sleep(seconds)