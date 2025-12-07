"""
Feature Extraction Service for Vestigo Backend
Orchestrates Ghidra headless analysis by calling extract_features.py script
This service does NOT implement feature extraction logic - it delegates to Ghidra
"""

import os
import subprocess
import json
import tempfile
from typing import Dict, Any, List
from pathlib import Path
import time

from config.logging_config import logger
from services.gnn_pipeline_service import GNNPipelineService

class FeatureExtractionService:
    """
    Service for orchestrating Ghidra-based feature extraction from binary files.
    
    This service acts as a wrapper that:
    1. Sets up Ghidra workspace
    2. Calls extract_features.py via Ghidra headless
    3. Reads and processes the resulting JSON output
    
    All actual feature extraction logic lives in ghidra_scripts/extract_features.py
    """
    
    def __init__(self):
        # Path to Ghidra and scripts
        self.ghidra_scripts_dir = Path(__file__).parent.parent.parent / "ghidra_scripts"
        self.extract_features_script = self.ghidra_scripts_dir / "extract_features.py"
        
        # Ghidra installation path (customize based on your setup)
        self.ghidra_path = os.environ.get("GHIDRA_HOME", "/opt/ghidra")
        self.ghidra_headless = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
        
        # Project root for output directory
        self.project_root = Path(__file__).parent.parent.parent
        
        # Path to enhanced crypto pipeline
        self.enhanced_pipeline_script = self.project_root / "enhanced_crypto_pipeline.py"
        
        # Initialize GNN pipeline service
        self.gnn_service = GNNPipelineService()
        
        # Check if pipeline script is available
        if not os.path.exists(self.enhanced_pipeline_script):
            logger.warning(f"Enhanced crypto pipeline not found: {self.enhanced_pipeline_script}")
            logger.warning("ML classification will be skipped")
        
        logger.info(f"FeatureExtractionService initialized")
        logger.info(f"Ghidra path: {self.ghidra_path}")
        logger.info(f"Extract features script: {self.extract_features_script}")
        logger.info(f"Enhanced pipeline script: {self.enhanced_pipeline_script}")
        logger.info(f"Output directory: {self.project_root / 'ghidra_json'}")
    
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
    
    async def extract_features_from_binary(self, job_id: str, binary_path: str) -> Dict[str, Any]:
        """
        Extract features from a binary file by calling Ghidra extract_features.py script
        
        This method orchestrates the Ghidra analysis but does NOT implement feature extraction.
        All extraction logic is in ghidra_scripts/extract_features.py
        
        Supports various binary formats:
        - ELF executables and object files (.o)
        - Archive files (.a) - will be processed by ingest module first to extract .o files
        - Binary files (.bin) - routed through appropriate analysis path
        
        Args:
            job_id: Unique identifier for this analysis job
            binary_path: Path to the binary file to analyze
            
        Returns:
            Dict containing extracted features and analysis results from Ghidra script
        """
        logger.info(f"Starting feature extraction - JobID: {job_id}, Binary: {binary_path}")
        
        if not os.path.exists(binary_path):
            logger.error(f"Binary file not found: {binary_path}")
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        # Create temporary directory for Ghidra analysis
        with tempfile.TemporaryDirectory(prefix=f"ghidra_analysis_{job_id}_") as temp_dir:
            logger.debug(f"Created temporary Ghidra workspace: {temp_dir}")
            
            try:
                # Call Ghidra to run extract_features.py script
                features_result = await self._run_ghidra_analysis(
                    binary_path, temp_dir, job_id
                )
                
                # Process and structure the JSON output from Ghidra script
                processed_features = self._process_ghidra_output(features_result, job_id)
                
                logger.info(f"Feature extraction completed - JobID: {job_id}")
                return processed_features
                
            except Exception as e:
                logger.error(f"Feature extraction failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
                raise
    
    async def _run_ghidra_analysis(self, binary_path: str, workspace_dir: str, job_id: str) -> Dict[str, Any]:
        """
        Run Ghidra headless to execute extract_features.py script
        
        This method sets up Ghidra workspace and calls analyzeHeadless with -postScript
        to execute the extract_features.py script. The script handles all analysis logic.
        """
        logger.info(f"Running Ghidra analysis - JobID: {job_id}")
        
        # Check Ghidra availability
        if not os.path.exists(self.ghidra_headless):
            logger.error(f"Ghidra headless not found at: {self.ghidra_headless}")
            logger.info("Please set GHIDRA_INSTALL_DIR environment variable or install Ghidra")
            raise FileNotFoundError(f"Ghidra headless script not found: {self.ghidra_headless}")
        
        if not os.path.exists(self.extract_features_script):
            logger.error(f"Extract features script not found: {self.extract_features_script}")
            raise FileNotFoundError(f"Extract features script not found: {self.extract_features_script}")
        
        # Delegate to Ghidra script execution
        return await self._run_real_ghidra_analysis(binary_path, workspace_dir, job_id)
    
    async def _run_real_ghidra_analysis(self, binary_path: str, workspace_dir: str, job_id: str) -> Dict[str, Any]:
        """
        Execute Ghidra analyzeHeadless with extract_features.py script
        
        The extract_features.py script:
        - Analyzes binary structure and functions
        - Extracts cryptographic signatures and constants
        - Computes entropy, graph features, and P-code analysis
        - Outputs results to ghidra_json/BINARY_NAME_features.json
        
        This method simply orchestrates the call and reads the output.
        """
        
        project_name = f"vestigo_analysis_{job_id}"
        
        # Resolve symlinks to get the actual binary name
        # Ghidra follows symlinks, so output file will be named after the target
        resolved_path = os.path.realpath(binary_path)
        binary_name = os.path.basename(resolved_path)
        original_name = os.path.basename(binary_path)
        
        if resolved_path != binary_path:
            logger.info(f"Resolved symlink: {original_name} -> {binary_name}")
        
        # extract_features.py script outputs to output_dir/BINARY_NAME_features.json
        # Pass full output directory path so script knows where to save
        output_dir = os.path.join(str(self.project_root), "ghidra_final_output")
        os.makedirs(output_dir, exist_ok=True)
        
        # Build Ghidra command
        # -import: Import binary into Ghidra project
        # -scriptPath: Add custom script directory
        # -postScript: Execute Python script after import
        # -deleteProject: Clean up workspace after analysis
        ghidra_cmd = [
            self.ghidra_headless,
            workspace_dir,                              # Ghidra workspace directory
            project_name,                               # Project name
            "-import", binary_path,                     # Import the binary
            "-scriptPath", str(self.extract_features_script.parent),  # Add our scripts directory
            "-postScript", self.extract_features_script.name, output_dir,  # Run extract_features.py
            "-deleteProject"                            # Clean up after analysis
        ]
        
        logger.info(f"Executing Ghidra analysis: analyzeHeadless with extract_features.py")
        logger.debug(f"Ghidra command: {' '.join(ghidra_cmd)}")
        
        try:
            # Execute Ghidra with extract_features.py script
            result = subprocess.run(
                ghidra_cmd,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minute timeout for complex binaries
                cwd=workspace_dir
            )
            
            if result.returncode != 0:
                logger.error(f"Ghidra script execution failed - JobID: {job_id}, Return code: {result.returncode}")
                logger.error(f"Ghidra stderr: {result.stderr}")
                logger.error(f"Ghidra stdout: {result.stdout}")
                raise RuntimeError(f"Ghidra analysis failed: {result.stderr}")
            
            logger.info(f"Ghidra script execution completed - JobID: {job_id}, Return code: {result.returncode}")
            if result.stdout:
                logger.info(f"Ghidra stdout: {result.stdout[:1000]}")  # Log first 1000 chars
            if result.stderr:
                logger.warning(f"Ghidra stderr: {result.stderr[:1000]}")  # Log first 1000 chars
            
            # Read the JSON output generated by extract_features.py
            # Script saves to: output_dir/BINARY_NAME_features.json
            expected_output = os.path.join(output_dir, f"{binary_name}_features.json")
            
            if os.path.exists(expected_output):
                with open(expected_output, 'r') as f:
                    features = json.load(f)
                logger.info(f"Loaded extract_features.py output - JobID: {job_id}, Functions: {len(features.get('functions', []))}")
                
                # Run both ML pipelines on the Ghidra JSON output in parallel
                # Both pipelines use the same Ghidra features as input
                
                # 1. Run Enhanced Crypto Pipeline (traditional ML model)
                logger.info(f"Running Enhanced Crypto Pipeline - JobID: {job_id}")
                enhanced_pipeline_output = await self._run_enhanced_pipeline(expected_output, binary_name, job_id)
                
                # 2. Run GNN Pipeline (graph neural network model)
                logger.info(f"Running GNN Pipeline - JobID: {job_id}")
                gnn_pipeline_output = await self.gnn_service.run_gnn_inference(expected_output, binary_name, job_id)
                
                # Merge both pipeline results into features
                features["pipeline_analysis"] = enhanced_pipeline_output
                features["gnn_analysis"] = gnn_pipeline_output
                
                logger.info(f"All ML pipelines completed - JobID: {job_id}")
                logger.info(f"Enhanced Pipeline Status: {enhanced_pipeline_output.get('status', 'unknown')}")
                logger.info(f"GNN Pipeline Status: {gnn_pipeline_output.get('status', 'unknown')}")
                
                return features
            else:
                logger.error(f"extract_features.py output not found: {expected_output}")
                # List available files for debugging
                ghidra_json_dir = os.path.join(str(self.project_root), "ghidra_json")
                if os.path.exists(ghidra_json_dir):
                    available_files = os.listdir(ghidra_json_dir)
                    logger.debug(f"Available files in ghidra_json: {available_files}")
                raise FileNotFoundError(f"Ghidra script output not found: {expected_output}")
                
        except subprocess.TimeoutExpired:
            logger.error(f"Ghidra script execution timeout - JobID: {job_id}")
            raise TimeoutError("Ghidra analysis timed out after 10 minutes")
        except Exception as e:
            logger.error(f"Ghidra script execution error - JobID: {job_id}, Error: {str(e)}")
            raise
    
    async def _run_enhanced_pipeline(self, ghidra_json_path: str, binary_name: str, job_id: str) -> Dict[str, Any]:
        """
        Run enhanced_crypto_pipeline.py on Ghidra JSON output
        
        This performs ML-based cryptographic algorithm classification on the
        extracted features from Ghidra analysis.
        
        Args:
            ghidra_json_path: Path to Ghidra JSON output file
            binary_name: Name of the binary being analyzed
            job_id: Job ID for tracking
            
        Returns:
            Dict containing pipeline analysis results (predictions, probabilities, etc.)
        """
        logger.info(f"Running enhanced crypto pipeline - JobID: {job_id}")
        
        if not os.path.exists(self.enhanced_pipeline_script):
            logger.warning(f"Enhanced pipeline script not found: {self.enhanced_pipeline_script}")
            logger.warning("Skipping ML classification step")
            return {
                "status": "skipped",
                "reason": "enhanced_crypto_pipeline.py not found"
            }
        
        # Create output path for pipeline results
        pipeline_output_dir = self.project_root / "pipeline_output"
        pipeline_output_dir.mkdir(exist_ok=True)
        
        pipeline_output_path = pipeline_output_dir / f"{binary_name}_pipeline.json"
        
        # Build pipeline command
        # python3 enhanced_crypto_pipeline.py --ghidra input.json --output output.json
        pipeline_cmd = [
            "python3",
            str(self.enhanced_pipeline_script),
            "--ghidra", str(ghidra_json_path),
            "--output", str(pipeline_output_path)
        ]
        
        logger.debug(f"Pipeline command: {' '.join(pipeline_cmd)}")
        
        try:
            # Run enhanced crypto pipeline
            result = subprocess.run(
                pipeline_cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout for ML inference
                cwd=str(self.project_root)
            )
            
            if result.returncode != 0:
                logger.error(f"Pipeline execution failed - JobID: {job_id}, Return code: {result.returncode}")
                logger.error(f"Pipeline stderr: {result.stderr}")
                logger.error(f"Pipeline stdout: {result.stdout}")
                return {
                    "status": "failed",
                    "error": result.stderr,
                    "stdout": result.stdout
                }
            
            logger.info(f"Pipeline execution completed - JobID: {job_id}")
            logger.debug(f"Pipeline output: {result.stdout}")
            
            # Read pipeline output
            if os.path.exists(pipeline_output_path):
                with open(pipeline_output_path, 'r') as f:
                    pipeline_result = json.load(f)
                
                logger.info(f"Loaded pipeline analysis - JobID: {job_id}")
                
                # Parse the enhanced pipeline output format
                # Structure: {analysis_metadata, file_analysis, function_analyses}
                result = {
                    "status": "success",
                    "pipeline_output_path": str(pipeline_output_path),
                    "ghidra_input_path": str(ghidra_json_path)
                }
                
                # Extract function-level predictions
                if "function_analyses" in pipeline_result:
                    function_analyses = pipeline_result["function_analyses"]
                    result["function_predictions"] = [
                        {
                            "function_name": func.get("function_info", {}).get("function_name"),
                            "function_address": func.get("function_info", {}).get("function_address"),
                            "predicted_algorithm": func.get("prediction", {}).get("predicted_algorithm"),
                            "confidence": func.get("prediction", {}).get("confidence"),
                            "is_crypto": func.get("encryption_analysis", {}).get("is_encrypted", False),
                            "encryption_status": func.get("encryption_analysis", {}).get("encryption_status"),
                            "top_3_predictions": func.get("top_predictions", [])[:3]
                        }
                        for func in function_analyses
                    ]
                
                # Extract file-level summary
                if "file_analysis" in pipeline_result:
                    file_analysis = pipeline_result["file_analysis"]
                    overall = file_analysis.get("overall_assessment", {})
                    algo_dist = file_analysis.get("algorithm_distribution", {})
                    
                    result["file_summary"] = {
                        "file_status": overall.get("file_status"),
                        "crypto_percentage": overall.get("crypto_percentage", 0),
                        "average_confidence": overall.get("average_confidence", 0),
                        "detected_algorithms": list(algo_dist.get("crypto_algorithm_counts", {}).keys()),
                        "algorithm_counts": algo_dist.get("counts", {}),
                        "top_algorithms": algo_dist.get("top_algorithms", []),
                        "confidence_scores": algo_dist.get("crypto_probability_analysis", {})
                    }
                
                # Add metadata
                if "analysis_metadata" in pipeline_result:
                    result["metadata"] = pipeline_result["analysis_metadata"]
                
                return result
            else:
                logger.error(f"Pipeline output not found: {pipeline_output_path}")
                return {
                    "status": "failed",
                    "error": f"Output file not generated: {pipeline_output_path}"
                }
                
        except subprocess.TimeoutExpired:
            logger.error(f"Pipeline execution timeout - JobID: {job_id}")
            return {
                "status": "timeout",
                "error": "Pipeline timed out after 5 minutes"
            }
        except Exception as e:
            logger.error(f"Pipeline execution error - JobID: {job_id}, Error: {str(e)}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _process_ghidra_output(self, ghidra_result: Dict[str, Any], job_id: str) -> Dict[str, Any]:
        """
        Process and structure the JSON output from extract_features.py script
        
        The Ghidra script (extract_features.py) outputs a comprehensive JSON with:
        - binary: Binary filename
        - metadata: Architecture, compiler, sections
        - functions: List of analyzed functions with features
        
        This method adds job tracking info and computes summary statistics.
        """
        logger.debug(f"Processing extract_features.py output - JobID: {job_id}")
        
        # Parse extract_features.py output format
        # Expected structure: {"binary": "name", "metadata": {...}, "functions": [...]}
        functions = ghidra_result.get("functions", [])
        metadata = ghidra_result.get("metadata", {})
        binary_name = ghidra_result.get("binary", "unknown")
        
        # Extract pipeline analysis if present
        pipeline_analysis = ghidra_result.get("pipeline_analysis", {})
        pipeline_status = pipeline_analysis.get("status", "not_run")
        
        # Extract GNN analysis if present
        gnn_analysis = ghidra_result.get("gnn_analysis", {})
        gnn_status = gnn_analysis.get("status", "not_run")
        
        # Compute summary statistics from extract_features.py output
        # Analyze function labels (crypto vs non-crypto) assigned by the script
        total_functions = len(functions)
        crypto_functions = len([f for f in functions if f.get("label", "Non-Crypto") != "Non-Crypto"])
        non_crypto_functions = total_functions - crypto_functions
        
        # If pipeline ran successfully, use its predictions for enhanced statistics
        if pipeline_status in ["success", "completed"]:
            logger.info(f"Enhanced Pipeline analysis available - incorporating ML predictions")
            
            # Extract predictions from pipeline results
            if "function_predictions" in pipeline_analysis:
                ml_predictions = pipeline_analysis["function_predictions"]
                crypto_functions_ml = sum(1 for pred in ml_predictions if pred.get("is_crypto", False))
                
                logger.info(f"Enhanced ML Classification: {crypto_functions_ml} crypto functions detected")
                
                # Store both static and ML-based counts
                crypto_functions_static = crypto_functions
                crypto_functions = crypto_functions_ml  # Use ML predictions
            
            # Extract file-level summary
            if "file_summary" in pipeline_analysis:
                file_summary = pipeline_analysis["file_summary"]
                logger.info(f"Detected algorithms (Enhanced): {', '.join(file_summary.get('detected_algorithms', []))}")
        
        # If GNN analysis ran successfully, add GNN predictions
        if gnn_status in ["success", "completed"]:
            logger.info(f"GNN Pipeline analysis available - incorporating GNN predictions")
            
            if "function_predictions" in gnn_analysis:
                gnn_predictions = gnn_analysis["function_predictions"]
                crypto_functions_gnn = sum(1 for pred in gnn_predictions if pred.get("is_crypto", False))
                
                logger.info(f"GNN Classification: {crypto_functions_gnn} crypto functions detected")
            
            if "algorithm_distribution" in gnn_analysis:
                gnn_algorithms = list(gnn_analysis["algorithm_distribution"].keys())
                logger.info(f"Detected algorithms (GNN): {', '.join(gnn_algorithms)}")
        
        # Count crypto constants detected by the script
        total_crypto_constants = sum(
            len(f.get("crypto_signatures", {}).get("detected_constants", []))
            for f in functions
        )
        
        # Calculate average entropy from script's entropy metrics
        avg_entropy = 0.0
        if functions:
            entropies = [f.get("entropy_metrics", {}).get("opcode_entropy", 0.0) for f in functions]
            avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        # Extract advanced features computed by the script
        advanced_features = {
            "total_tables_detected": metadata.get("total_tables_detected", 0),
            "text_size": metadata.get("text_size", 0),
            "rodata_size": metadata.get("rodata_size", 0),
            "data_size": metadata.get("data_size", 0)
        }
        
        # Structure final result with job metadata
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
            "functions": functions,  # Full function analysis from extract_features.py
            "metadata": metadata,    # Binary metadata from extract_features.py
            "analysis_tool": "ghidra_extract_features",
            "next_step": "classification_ready"
        }
        
        # Add pipeline analysis results if available
        if pipeline_status in ["success", "completed"]:
            processed_result["ml_classification"] = {
                "status": "completed",
                "model_type": "enhanced_crypto_pipeline",
                "function_predictions": pipeline_analysis.get("function_predictions", []),
                "file_summary": pipeline_analysis.get("file_summary", {}),
                "detected_algorithms": pipeline_analysis.get("file_summary", {}).get("detected_algorithms", []),
                "confidence_scores": pipeline_analysis.get("file_summary", {}).get("confidence_scores", {}),
                "pipeline_output_path": pipeline_analysis.get("pipeline_output_path")
            }
            processed_result["next_step"] = "ml_classification_complete"
        elif pipeline_status == "skipped":
            processed_result["ml_classification"] = {
                "status": "skipped",
                "model_type": "enhanced_crypto_pipeline",
                "reason": pipeline_analysis.get("reason", "Pipeline not available")
            }
        elif pipeline_status in ["failed", "timeout", "error"]:
            processed_result["ml_classification"] = {
                "status": "failed",
                "model_type": "enhanced_crypto_pipeline",
                "error": pipeline_analysis.get("error", "Unknown error"),
                "details": pipeline_analysis
            }
        
        # Add GNN analysis results if available
        if gnn_status in ["success", "completed"]:
            processed_result["gnn_classification"] = {
                "status": "completed",
                "model_type": "graph_neural_network",
                "function_predictions": gnn_analysis.get("function_predictions", []),
                "summary": gnn_analysis.get("summary", {}),
                "algorithm_distribution": gnn_analysis.get("algorithm_distribution", {}),
                "binary_info": gnn_analysis.get("binary_info", {}),
                "gnn_output_path": gnn_analysis.get("gnn_output_path")
            }
        elif gnn_status == "skipped":
            processed_result["gnn_classification"] = {
                "status": "skipped",
                "model_type": "graph_neural_network",
                "reason": gnn_analysis.get("reason", "GNN not available")
            }
        elif gnn_status in ["failed", "timeout", "error"]:
            processed_result["gnn_classification"] = {
                "status": "failed",
                "model_type": "graph_neural_network",
                "error": gnn_analysis.get("error", "Unknown error"),
                "details": gnn_analysis
            }
        
        logger.info(f"extract_features.py output processed - JobID: {job_id}, Binary: {binary_name}")
        logger.info(f"Functions: {total_functions}, Crypto: {crypto_functions}, "
                   f"Constants: {total_crypto_constants}, Avg Entropy: {avg_entropy:.4f}")
        
        if pipeline_status in ["success", "completed"]:
            detected_algos = processed_result["ml_classification"]["detected_algorithms"]
            logger.info(f"Enhanced ML Classification: Detected algorithms: {', '.join(detected_algos) if detected_algos else 'None'}")
        
        if gnn_status in ["success", "completed"]:
            gnn_algos = list(processed_result["gnn_classification"]["algorithm_distribution"].keys())
            logger.info(f"GNN Classification: Detected algorithms: {', '.join(gnn_algos) if gnn_algos else 'None'}")
        
        return processed_result