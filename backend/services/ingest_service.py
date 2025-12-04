"""
Ingest Service for Vestigo Backend
Handles file ingestion, routing decisions, and initial analysis setup
"""

import os
import sys
import tempfile
import shutil
from typing import Dict, Any, Optional
import uuid
from pathlib import Path

# Add parent directory to path to import ingest module
parent_dir = Path(__file__).parent.parent.parent
sys.path.append(str(parent_dir))

from ingest import IngestionModule
from config.logging_config import logger

class IngestService:
    """Service for handling file ingestion and routing decisions"""
    
    def __init__(self, analysis_workspace_base: str = "./analysis_workspace"):
        self.analysis_workspace_base = os.path.abspath(analysis_workspace_base)
        self.ingest_module = IngestionModule(output_base_dir=self.analysis_workspace_base)
        logger.info(f"IngestService initialized with workspace: {self.analysis_workspace_base}")
    
    async def process_uploaded_file(self, file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        Process an uploaded file through the ingest pipeline
        
        Args:
            file_content (bytes): Raw file content
            filename (str): Original filename

        Returns:
            Dict containing analysis results and routing information
        """
        job_id = str(uuid.uuid4())
        logger.info(f"Processing file upload - JobID: {job_id}, Filename: {filename}")
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as temp_file:
            temp_file.write(file_content)
            temp_file_path = temp_file.name
        
        try:
            logger.debug(f"Created temporary file: {temp_file_path}")
            
            # Process file with ingest module
            logger.info(f"Starting ingest analysis for JobID: {job_id}")
            ingest_result = self.ingest_module.process(temp_file_path)
            
            logger.info(f"Ingest analysis completed - JobID: {job_id}, Route: {ingest_result['routing']['decision']}")
            
            # Prepare structured response
            response = self._prepare_response(job_id, filename, len(file_content), ingest_result)
            
            logger.debug(f"Response prepared for JobID: {job_id}")
            return response
            
        except Exception as e:
            logger.error(f"Error processing file upload - JobID: {job_id}, Error: {str(e)}", exc_info=True)
            raise
        finally:
            # Clean up temporary file
            if os.path.exists(temp_file_path):
                os.unlink(temp_file_path)
                logger.debug(f"Cleaned up temporary file: {temp_file_path}")
    
    def _prepare_response(self, job_id: str, filename: str, file_size: int, ingest_result: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare structured response for frontend consumption"""
        
        routing_decision = ingest_result["routing"]["decision"]
        logger.debug(f"Preparing response for JobID: {job_id}, Route: {routing_decision}")
        
        response = {
            "jobId": job_id,
            "fileName": filename,
            "fileSize": self._format_size(file_size),
            "fileSizeBytes": file_size,
            "status": "analyzed",
            "analysis": {
                "routing_decision": routing_decision,
                "routing_reason": ingest_result["routing"]["reason"],
                "file_type": ingest_result["file_info"]["detected_type"],
                "extraction_success": ingest_result["extraction"]["was_extracted"],
                "next_steps": ingest_result["next_steps"],
                "workspace_path": ingest_result.get("analysis_workspace")
            },
            "processing": {
                "ingest_complete": True,
                "ready_for_next_step": True
            }
        }
        
        # Add routing-specific information
        if routing_decision == "PATH_A_BARE_METAL":
            self._add_bare_metal_info(response, ingest_result)
        elif routing_decision == "PATH_B_LINUX_FS":
            self._add_linux_fs_info(response, ingest_result)
        elif routing_decision == "PATH_C_HARD_TARGET":
            self._add_hard_target_info(response, ingest_result)
        
        logger.debug(f"Response structure complete for JobID: {job_id}")
        return response
    
    def _add_bare_metal_info(self, response: Dict[str, Any], ingest_result: Dict[str, Any]):
        """Add PATH_A_BARE_METAL specific information"""
        binary_analysis = ingest_result.get("binary_analysis", {})
        
        response["analysis"]["binary_info"] = {
            "is_binary": True,
            "analysis_ready": binary_analysis.get("processed", False),
            "features_extracted": binary_analysis.get("features_extracted", False),
            "classification_complete": binary_analysis.get("classification_complete", False),
            "analysis_type": binary_analysis.get("analysis_type", "unknown"),
            "file_path": binary_analysis.get("file_path")
        }
        
        response["next_actions"] = [
            {
                "action": "extract_features",
                "endpoint": f"/job/{response['jobId']}/extract-features",
                "description": "Extract binary features using Ghidra analysis",
                "ready": True
            },
            {
                "action": "classify_crypto", 
                "endpoint": f"/job/{response['jobId']}/classify",
                "description": "Classify cryptographic functions",
                "ready": False,  # Available after feature extraction
                "depends_on": "extract_features"
            }
        ]
        
        logger.info(f"Added PATH_A_BARE_METAL info for JobID: {response['jobId']}")
    
    def _add_linux_fs_info(self, response: Dict[str, Any], ingest_result: Dict[str, Any]):
        """Add PATH_B_LINUX_FS specific information"""
        response["analysis"]["filesystem_info"] = {
            "is_filesystem": True,
            "extracted_path": ingest_result["extraction"].get("extracted_path")
        }
        
        response["next_actions"] = [
            {
                "action": "scan_filesystem",
                "endpoint": f"/job/{response['jobId']}/fs-scan", 
                "description": "Scan extracted filesystem for binaries",
                "ready": True
            }
        ]
        
        logger.info(f"Added PATH_B_LINUX_FS info for JobID: {response['jobId']}")
    
    def _add_hard_target_info(self, response: Dict[str, Any], ingest_result: Dict[str, Any]):
        """Add PATH_C_HARD_TARGET specific information"""
        response["analysis"]["hard_target_info"] = {
            "is_encrypted": True,
            "extraction_failed": not ingest_result["extraction"]["was_extracted"]
        }
        
        response["next_actions"] = [
            {
                "action": "entropy_analysis",
                "endpoint": f"/job/{response['jobId']}/entropy",
                "description": "Analyze file entropy for encryption detection", 
                "ready": True
            },
            {
                "action": "signature_detection",
                "endpoint": f"/job/{response['jobId']}/signatures",
                "description": "Detect file signatures and magic bytes",
                "ready": True
            }
        ]
        
        logger.info(f"Added PATH_C_HARD_TARGET info for JobID: {response['jobId']}")
    
    def _format_size(self, bytes_size: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific job (placeholder for database integration)"""
        logger.info(f"Getting job status for JobID: {job_id}")
        
        # TODO: Implement database lookup
        # For now, return a placeholder response
        return {
            "jobId": job_id,
            "status": "not_found",
            "message": "Job status lookup not yet implemented with database"
        }