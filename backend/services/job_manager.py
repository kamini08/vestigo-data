"""
Job Management Service for Vestigo Backend
Handles job state management and tracking throughout the analysis pipeline
"""

import json
import os
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

from config.logging_config import logger

class JobStatus(Enum):
    PENDING = "pending"
    INGESTING = "ingesting"
    INGEST_COMPLETE = "ingest_complete"
    EXTRACTING_FEATURES = "extracting_features"
    FEATURES_COMPLETE = "features_complete"
    CLASSIFYING = "classifying"
    COMPLETE = "complete"
    FAILED = "failed"

@dataclass
class JobData:
    job_id: str
    filename: str
    file_size: int
    status: JobStatus
    routing_decision: Optional[str] = None
    routing_reason: Optional[str] = None
    file_type: Optional[str] = None
    workspace_path: Optional[str] = None
    analysis_results: Optional[Dict[str, Any]] = None
    feature_extraction_results: Optional[Dict[str, Any]] = None
    classification_results: Optional[Dict[str, Any]] = None
    created_at: float = None
    updated_at: float = None
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        self.updated_at = time.time()

class JobManager:
    """Manages job state and persistence"""
    
    def __init__(self, storage_dir: str = "./job_storage"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self._jobs_cache: Dict[str, JobData] = {}
        logger.info(f"JobManager initialized with storage: {self.storage_dir}")
    
    def create_job(self, job_id: str, filename: str, file_size: int) -> JobData:
        """Create a new job"""
        job = JobData(
            job_id=job_id,
            filename=filename,
            file_size=file_size,
            status=JobStatus.PENDING
        )
        
        self._save_job(job)
        self._jobs_cache[job_id] = job
        
        logger.info(f"Created new job - JobID: {job_id}, File: {filename}")
        return job
    
    def update_job_status(self, job_id: str, status: JobStatus, **kwargs) -> Optional[JobData]:
        """Update job status and additional fields"""
        job = self.get_job(job_id)
        if not job:
            logger.warning(f"Attempted to update non-existent job: {job_id}")
            return None
        
        job.status = status
        job.updated_at = time.time()
        
        # Update additional fields
        for key, value in kwargs.items():
            if hasattr(job, key):
                setattr(job, key, value)
        
        self._save_job(job)
        self._jobs_cache[job_id] = job
        
        logger.info(f"Updated job status - JobID: {job_id}, Status: {status.value}")
        return job
    
    def update_job_ingest_results(self, job_id: str, ingest_results: Dict[str, Any]) -> Optional[JobData]:
        """Update job with ingest analysis results"""
        return self.update_job_status(
            job_id, 
            JobStatus.INGEST_COMPLETE,
            routing_decision=ingest_results["routing"]["decision"],
            routing_reason=ingest_results["routing"]["reason"],
            file_type=ingest_results["file_info"]["detected_type"],
            workspace_path=ingest_results.get("analysis_workspace"),
            analysis_results=ingest_results
        )
    
    def update_job_feature_results(self, job_id: str, feature_results: Dict[str, Any]) -> Optional[JobData]:
        """Update job with feature extraction results"""
        return self.update_job_status(
            job_id,
            JobStatus.FEATURES_COMPLETE,
            feature_extraction_results=feature_results
        )
    
    def update_job_classification_results(self, job_id: str, classification_results: Dict[str, Any]) -> Optional[JobData]:
        """Update job with classification results"""
        return self.update_job_status(
            job_id,
            JobStatus.COMPLETE,
            classification_results=classification_results
        )
    
    def mark_job_failed(self, job_id: str, error_message: str) -> Optional[JobData]:
        """Mark job as failed with error message"""
        return self.update_job_status(
            job_id,
            JobStatus.FAILED,
            error_message=error_message
        )
    
    def get_job(self, job_id: str) -> Optional[JobData]:
        """Get job by ID"""
        # Check cache first
        if job_id in self._jobs_cache:
            return self._jobs_cache[job_id]
        
        # Load from storage
        job_file = self.storage_dir / f"{job_id}.json"
        if job_file.exists():
            try:
                with open(job_file, 'r') as f:
                    job_dict = json.load(f)
                
                # Convert status back to enum
                job_dict['status'] = JobStatus(job_dict['status'])
                job = JobData(**job_dict)
                
                # Cache it
                self._jobs_cache[job_id] = job
                return job
                
            except Exception as e:
                logger.error(f"Error loading job {job_id}: {str(e)}")
                return None
        
        return None
    
    def get_all_jobs(self, limit: int = 100) -> List[JobData]:
        """Get all jobs, most recent first"""
        jobs = []
        
        # Load all job files
        for job_file in self.storage_dir.glob("*.json"):
            job_id = job_file.stem
            job = self.get_job(job_id)
            if job:
                jobs.append(job)
        
        # Sort by created_at (most recent first)
        jobs.sort(key=lambda x: x.created_at, reverse=True)
        
        return jobs[:limit]
    
    def delete_job(self, job_id: str) -> bool:
        """Delete a job"""
        job_file = self.storage_dir / f"{job_id}.json"
        
        try:
            if job_file.exists():
                job_file.unlink()
            
            # Remove from cache
            if job_id in self._jobs_cache:
                del self._jobs_cache[job_id]
            
            logger.info(f"Deleted job: {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting job {job_id}: {str(e)}")
            return False
    
    def _save_job(self, job: JobData):
        """Save job to storage"""
        job_file = self.storage_dir / f"{job.job_id}.json"
        
        try:
            # Convert to dict and handle enum
            job_dict = asdict(job)
            job_dict['status'] = job.status.value
            
            with open(job_file, 'w') as f:
                json.dump(job_dict, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving job {job.job_id}: {str(e)}")
            raise
    
    def get_job_summary(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get a summary of job for API responses"""
        job = self.get_job(job_id)
        if not job:
            return None
        
        summary = {
            "jobId": job.job_id,
            "fileName": job.filename,
            "fileSize": self._format_size(job.file_size),
            "status": job.status.value,
            "createdAt": job.created_at,
            "updatedAt": job.updated_at
        }
        
        if job.routing_decision:
            summary["routing"] = {
                "decision": job.routing_decision,
                "reason": job.routing_reason
            }
        
        if job.error_message:
            summary["error"] = job.error_message
        
        # Add progress information
        if job.status == JobStatus.INGEST_COMPLETE:
            summary["progress"] = {
                "ingest": True,
                "features": False,
                "classification": False
            }
        elif job.status == JobStatus.FEATURES_COMPLETE:
            summary["progress"] = {
                "ingest": True,
                "features": True,
                "classification": False
            }
        elif job.status == JobStatus.COMPLETE:
            summary["progress"] = {
                "ingest": True,
                "features": True,
                "classification": True
            }
        
        return summary
    
    def _format_size(self, bytes_size: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} TB"

# Global job manager instance
job_manager = JobManager()