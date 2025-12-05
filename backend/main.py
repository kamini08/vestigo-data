import hashlib
import random
import mimetypes
import traceback
import sys
import os
import glob
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from prisma import Prisma
from datetime import datetime

# Add current directory to path for imports
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

# Import our services
from config.logging_config import logger
from services.ingest_service import IngestService
from services.feature_extraction_service import FeatureExtractionService
from services.filesystem_scan_service import FilesystemScanService
from services.secure_boot_analysis_service import SecureBootAnalysisService
from services.crypto_library_service import CryptoLibraryService
from services.job_manager import job_manager, JobStatus

# ==========================================================
# FASTAPI APP
# ==========================================================

app = FastAPI(title="Vestigo Backend")

# Initialize services
ingest_service = IngestService()
feature_service = FeatureExtractionService()
filesystem_service = FilesystemScanService()
secureboot_service = SecureBootAnalysisService()
cryptolib_service = CryptoLibraryService()

logger.info("Vestigo Backend starting up...")

# ==========================================================
# CORS CONFIG
# ==========================================================

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "https://your-production-domain.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# DATABASE (PRISMA)
# ==========================================================

db = Prisma()


@app.on_event("startup")
async def startup():
    logger.info("🔌 Connecting to database…")
    await db.connect()
    logger.info("✅ Database connected.")
    logger.info("🚀 Vestigo Backend ready")


@app.on_event("shutdown")
async def shutdown():
    logger.info("🔌 Disconnecting database…")
    await db.disconnect()
    logger.info("🛑 Database disconnected.")
    logger.info("👋 Vestigo Backend shutdown complete")


# ==========================================================
# HELPERS
# ==========================================================

CRYPTO_TYPES = [
    ("AES", "AES-128", "High", "Symmetric block cipher detected"),
    ("AES", "AES-256", "Critical", "Strong AES block detected"),
    ("RSA", "RSA-1024", "Medium", "RSA key operations found"),
    ("ECC", "Curve25519", "High", "ECC operations detected"),
    ("SHA", "SHA-256", "Low", "Hashing function present"),
    ("XOR", "XOR Loop", "Critical", "Weak obfuscation loop found"),
]


def analyze(content: bytes):
    findings = []
    count = random.randint(0, 5)

    for _ in range(count):
        name, variant, sev, desc = random.choice(CRYPTO_TYPES)
        findings.append({
            "name": name,
            "algorithm": name,
            "variant": variant,
            "severity": sev,
            "description": desc,
        })

    return findings, count


def generate_hash(data: bytes):
    return hashlib.md5(data).hexdigest()


def detect_type(filename: str):
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/octet-stream"


def format_size(bytes_len: int):
    return f"{bytes_len / 1024 / 1024:.2f} MB"


def severity_level(count: int):
    if count == 0:
        return "safe"
    if count == 1:
        return "low"
    if 2 <= count <= 3:
        return "high"
    return "critical"


# ==========================================================
# ROUTES
# ==========================================================

@app.get("/")
def home():
    return {"message": "Vestigo Backend Running"}


# ----------------------------------------------------------
# UPLOAD + ANALYZE
# ----------------------------------------------------------
@app.post("/analyze")
async def upload_and_analyze(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Main endpoint for file analysis - integrates with ingest service
    """
    try:
        if file is None:
            logger.error("No file provided in upload")
            raise HTTPException(status_code=400, detail="No file provided")

        # Read file content
        content = await file.read()
        if not content:
            logger.error(f"Empty file uploaded: {file.filename}")
            raise HTTPException(status_code=400, detail="Empty file uploaded")

        logger.info(f"Processing file upload: {file.filename} ({len(content)} bytes)")

        # Process through ingest service
        analysis_result = await ingest_service.process_uploaded_file(content, file.filename)
        job_id = analysis_result["jobId"]

        # Create job in our job manager
        job = job_manager.create_job(job_id, file.filename, len(content))

        # Update job with ingest results - extract from analysis_result structure
        if "analysis" in analysis_result:
            # Prepare ingest results structure for job manager
            ingest_results = {
                "routing": {
                    "decision": analysis_result["analysis"]["routing_decision"],
                    "reason": analysis_result["analysis"]["routing_reason"]
                },
                "file_info": {
                    "detected_type": analysis_result["analysis"]["file_type"]
                },
                "extraction": {
                    "was_extracted": analysis_result["analysis"]["extraction_success"]
                },
                "analysis_workspace": analysis_result["analysis"]["workspace_path"]
            }
            
            # Add bootloaders if found
            if "bootloaders" in analysis_result["analysis"]:
                ingest_results["bootloaders"] = analysis_result["analysis"]["bootloaders"]
            
            job_manager.update_job_ingest_results(job_id, ingest_results)

        # If it's PATH_A_BARE_METAL, add background task for feature extraction
        if analysis_result["analysis"]["routing_decision"] == "PATH_A_BARE_METAL":
            background_tasks.add_task(process_bare_metal_features, job_id, analysis_result)
        
        # If it's PATH_B_LINUX_FS, add background task for filesystem scanning
        elif analysis_result["analysis"]["routing_decision"] == "PATH_B_LINUX_FS":
            background_tasks.add_task(process_filesystem_scan, job_id, analysis_result)
            
            # If bootloaders were found, create separate jobs for each
            if "bootloaders" in analysis_result["analysis"]:
                bootloaders = analysis_result["analysis"]["bootloaders"]
                if bootloaders:
                    logger.info(f"Creating separate jobs for {len(bootloaders)} bootloader(s)")
                    background_tasks.add_task(process_bootloader_analyses, job_id, bootloaders)

        logger.info(f"Analysis initiated successfully - JobID: {job_id}")
        return analysis_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


async def process_bare_metal_features(job_id: str, analysis_result: dict):
    """Background task to process PATH_A_BARE_METAL feature extraction"""
    try:
        logger.info(f"Starting background feature extraction - JobID: {job_id}")
        
        # Update job status
        job_manager.update_job_status(job_id, JobStatus.EXTRACTING_FEATURES)
        
        # Get binary file path from analysis results
        binary_info = analysis_result["analysis"].get("binary_info", {})
        workspace_path = analysis_result["analysis"]["workspace_path"]
        
        # For PATH_A_BARE_METAL, the binary file should be in the workspace
        if workspace_path:
            # Look for the binary file in workspace
            import glob
            workspace_files = glob.glob(os.path.join(workspace_path, "*"))
            binary_files = [f for f in workspace_files if os.path.isfile(f) and not f.endswith('.json')]
            
            if binary_files:
                binary_path = binary_files[0]  # Use first binary file found
                logger.info(f"Found binary file for extraction - JobID: {job_id}, Path: {binary_path}")
                
                # Run feature extraction
                feature_results = await feature_service.extract_features_from_binary(job_id, binary_path)
                
                # Update job with results
                job_manager.update_job_feature_results(job_id, feature_results)
                
                logger.info(f"Background feature extraction completed - JobID: {job_id}")
            else:
                logger.error(f"No binary files found in workspace - JobID: {job_id}")
                job_manager.mark_job_failed(job_id, "No binary files found for feature extraction")
        else:
            logger.error(f"No workspace path available - JobID: {job_id}")
            job_manager.mark_job_failed(job_id, "Workspace path not available")
            
    except Exception as e:
        logger.error(f"Background feature extraction failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
        job_manager.mark_job_failed(job_id, f"Feature extraction failed: {str(e)}")


async def process_filesystem_scan(job_id: str, analysis_result: dict):
    """Background task to process PATH_B_LINUX_FS filesystem scanning"""
    try:
        logger.info(f"Starting background filesystem scan - JobID: {job_id}")
        
        # Update job status
        job_manager.update_job_status(job_id, JobStatus.EXTRACTING_FEATURES)
        
        # Get extracted filesystem path from analysis results
        extracted_path = None
        if "analysis" in analysis_result:
            if "filesystem_info" in analysis_result["analysis"]:
                extracted_path = analysis_result["analysis"]["filesystem_info"].get("extracted_path")
            elif "workspace_path" in analysis_result["analysis"]:
                # Fallback to workspace path
                workspace_path = analysis_result["analysis"]["workspace_path"]
                # Check if there's an extracted directory in the workspace
                if workspace_path and os.path.exists(workspace_path):
                    for item in os.listdir(workspace_path):
                        item_path = os.path.join(workspace_path, item)
                        if os.path.isdir(item_path):
                            extracted_path = item_path
                            break
        
        if extracted_path and os.path.exists(extracted_path):
            logger.info(f"Found extracted filesystem - JobID: {job_id}, Path: {extracted_path}")
            
            # Run filesystem scan
            scan_results = await filesystem_service.scan_filesystem(job_id, extracted_path)
            
            # Update job with results (using feature_extraction_results for now)
            job_manager.update_job_feature_results(job_id, scan_results)
            
            # If crypto libraries were found, process them
            if "crypto_libraries" in scan_results:
                crypto_libs = scan_results["crypto_libraries"]
                if crypto_libs.get("so_files") or crypto_libs.get("a_files"):
                    total_libs = len(crypto_libs.get("so_files", [])) + len(crypto_libs.get("a_files", []))
                    logger.info(f"Processing {total_libs} crypto libraries found in filesystem scan")
                    await process_crypto_libraries(job_id, crypto_libs)
            
            logger.info(f"Background filesystem scan completed - JobID: {job_id}")
        else:
            logger.error(f"Extracted filesystem path not found - JobID: {job_id}")
            job_manager.mark_job_failed(job_id, "Extracted filesystem path not available")
            
    except Exception as e:
        logger.error(f"Background filesystem scan failed - JobID: {job_id}, Error: {str(e)}", exc_info=True)
        job_manager.mark_job_failed(job_id, f"Filesystem scan failed: {str(e)}")


async def process_bootloader_analyses(parent_job_id: str, bootloaders: list):
    """Background task to create separate jobs for bootloader secure boot analysis"""
    try:
        logger.info(f"Starting bootloader analysis jobs - ParentJob: {parent_job_id}, Count: {len(bootloaders)}")
        
        import uuid
        
        for bootloader_info in bootloaders:
            # Create a new job for each bootloader analysis
            bootloader_job_id = str(uuid.uuid4())
            bootloader_name = bootloader_info.get("file", "unknown")
            
            logger.info(f"Creating bootloader analysis job - JobID: {bootloader_job_id}, Bootloader: {bootloader_name}")
            
            # Create job with bootloader- prefix for easy identification
            job = job_manager.create_job(
                bootloader_job_id, 
                f"bootloader-{bootloader_name}",
                bootloader_info.get("size", 0)
            )
            
            # Mark as bootloader analysis type
            job_manager.update_job_status(
                bootloader_job_id,
                JobStatus.EXTRACTING_FEATURES,
                routing_decision="BOOTLOADER_ANALYSIS",
                routing_reason=f"Secure boot analysis for {bootloader_info.get('type', 'unknown')} bootloader",
                workspace_path=f"parent:{parent_job_id}"
            )
            
            # Run secure boot analysis
            try:
                analysis_results = await secureboot_service.analyze_bootloader(
                    parent_job_id,
                    bootloader_info.get("path"),
                    bootloader_info
                )
                
                # Update job with results
                job_manager.update_job_feature_results(bootloader_job_id, analysis_results)
                
                logger.info(f"Bootloader analysis completed - JobID: {bootloader_job_id}")
                
            except Exception as e:
                logger.error(f"Bootloader analysis failed - JobID: {bootloader_job_id}, Error: {str(e)}")
                job_manager.mark_job_failed(bootloader_job_id, f"Bootloader analysis failed: {str(e)}")
        
        logger.info(f"All bootloader analysis jobs created - ParentJob: {parent_job_id}")
        
    except Exception as e:
        logger.error(f"Failed to create bootloader analysis jobs - ParentJob: {parent_job_id}, Error: {str(e)}", exc_info=True)


async def process_crypto_libraries(parent_job_id: str, crypto_libs: dict):
    """Background task to process crypto libraries (.so and .a files)"""
    try:
        logger.info(f"Starting crypto library processing - ParentJob: {parent_job_id}")
        
        # Process libraries using CryptoLibraryService
        results = cryptolib_service.process_crypto_libraries(crypto_libs, parent_job_id)
        
        logger.info(f"Crypto library processing complete - ParentJob: {parent_job_id}, Summary: {results.get('summary', {})}")
        
        # Get all files ready for PATH_A pipeline
        pipeline_files = cryptolib_service.get_objects_for_pipeline(results)
        
        if pipeline_files:
            logger.info(f"Creating {len(pipeline_files)} analysis jobs for crypto library objects")
            
            import uuid
            
            # Create separate jobs for each object file from .a archives
            for file_info in pipeline_files:
                if file_info.get("analysis_type") == "object_file_analysis":
                    # This is a .o file extracted from .a archive
                    object_job_id = str(uuid.uuid4())
                    
                    job = job_manager.create_job(
                        object_job_id,
                        file_info["file"],
                        file_info["size"]
                    )
                    
                    job_manager.update_job_status(
                        object_job_id,
                        JobStatus.EXTRACTING_FEATURES,
                        routing_decision="PATH_A_BARE_METAL",
                        routing_reason=f"Object file from {file_info.get('parent_archive', 'archive')}",
                        workspace_path=file_info["path"]
                    )
                    
                    # Run feature extraction on the .o file
                    try:
                        features = await feature_service.extract_features_from_binary(object_job_id, file_info["path"])
                        job_manager.update_job_feature_results(object_job_id, features)
                        
                        logger.info(f"Object file analysis completed - JobID: {object_job_id}, File: {file_info['file']}")
                        
                    except Exception as e:
                        logger.error(f"Object file analysis failed - JobID: {object_job_id}, Error: {str(e)}")
                        job_manager.mark_job_failed(object_job_id, f"Analysis failed: {str(e)}")
                
                elif file_info.get("type") == "shared_object":
                    # This is a .so file - analyze directly
                    so_job_id = str(uuid.uuid4())
                    
                    job = job_manager.create_job(
                        so_job_id,
                        file_info["file"],
                        file_info["size"]
                    )
                    
                    job_manager.update_job_status(
                        so_job_id,
                        JobStatus.EXTRACTING_FEATURES,
                        routing_decision="PATH_A_BARE_METAL",
                        routing_reason="Shared object library analysis",
                        workspace_path=file_info["path"]
                    )
                    
                    # Run feature extraction on the .so file
                    try:
                        features = await feature_service.extract_features_from_binary(so_job_id, file_info["path"])
                        job_manager.update_job_feature_results(so_job_id, features)
                        
                        logger.info(f"Shared object analysis completed - JobID: {so_job_id}, File: {file_info['file']}")
                        
                    except Exception as e:
                        logger.error(f"Shared object analysis failed - JobID: {so_job_id}, Error: {str(e)}")
                        job_manager.mark_job_failed(so_job_id, f"Analysis failed: {str(e)}")
        
        logger.info(f"All crypto library jobs completed - ParentJob: {parent_job_id}")
        
    except Exception as e:
        logger.error(f"Crypto library processing failed - ParentJob: {parent_job_id}, Error: {str(e)}", exc_info=True)


# ==========================================================
# JOB MANAGEMENT ENDPOINTS
# ==========================================================

@app.get("/job/{job_id}")
async def get_job_details(job_id: str):
    """Get detailed information about a specific job"""
    try:
        job_summary = job_manager.get_job_summary(job_id)
        if not job_summary:
            raise HTTPException(status_code=404, detail="Job not found")
        
        # Get full job details
        job = job_manager.get_job(job_id)
        
        response = {
            **job_summary,
            "analysis": job.analysis_results if job.analysis_results else {},
            "features": job.feature_extraction_results if job.feature_extraction_results else {},
            "classification": job.classification_results if job.classification_results else {}
        }
        
        logger.debug(f"Retrieved job details - JobID: {job_id}")
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving job {job_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving job details")


@app.get("/job/{job_id}/features")
async def get_job_features(job_id: str):
    """Get extracted features for a job"""
    try:
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if not job.feature_extraction_results:
            raise HTTPException(status_code=404, detail="Features not yet extracted")
        
        return {
            "jobId": job_id,
            "features": job.feature_extraction_results,
            "status": "features_available"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving features for job {job_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving features")


@app.post("/job/{job_id}/extract-features")
async def trigger_feature_extraction(job_id: str, background_tasks: BackgroundTasks):
    """Manually trigger feature extraction for a job"""
    try:
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if job.routing_decision != "PATH_A_BARE_METAL":
            raise HTTPException(status_code=400, detail="Feature extraction only available for PATH_A_BARE_METAL")
        
        if job.status == JobStatus.EXTRACTING_FEATURES:
            return {"message": "Feature extraction already in progress"}
        
        # Add background task
        background_tasks.add_task(process_bare_metal_features, job_id, job.analysis_results)
        
        return {
            "message": "Feature extraction started",
            "jobId": job_id,
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering feature extraction for job {job_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error starting feature extraction")


@app.post("/job/{job_id}/fs-scan")
async def trigger_filesystem_scan(job_id: str, background_tasks: BackgroundTasks):
    """Manually trigger filesystem scan for a PATH_B_LINUX_FS job"""
    try:
        job = job_manager.get_job(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Job not found")
        
        if job.routing_decision != "PATH_B_LINUX_FS":
            raise HTTPException(status_code=400, detail="Filesystem scan only available for PATH_B_LINUX_FS")
        
        if job.status == JobStatus.EXTRACTING_FEATURES:
            return {"message": "Filesystem scan already in progress"}
        
        # Add background task
        background_tasks.add_task(process_filesystem_scan, job_id, job.analysis_results)
        
        return {
            "message": "Filesystem scan started",
            "jobId": job_id,
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error triggering filesystem scan for job {job_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error starting filesystem scan")


@app.get("/jobs")
async def list_jobs(limit: int = 50):
    """List all jobs"""
    try:
        jobs = job_manager.get_all_jobs(limit=limit)
        job_summaries = [job_manager.get_job_summary(job.job_id) for job in jobs]
        
        return {
            "jobs": job_summaries,
            "total": len(job_summaries)
        }
        
    except Exception as e:
        logger.error(f"Error listing jobs: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving jobs")


# ==========================================================
# LEGACY ENDPOINTS (For backward compatibility)
# ==========================================================

@app.get("/jobs/{job_id}")
async def get_legacy_job(job_id: str):
    """Legacy endpoint for backward compatibility with old frontend"""
    try:
        job = await db.job.find_unique(
            where={"id": job_id},
            include={"threats": True}
        )

        if not job:
            return {"error": "Job not found"}

        return job
    except Exception as e:
        logger.error(f"Error in legacy job endpoint: {str(e)}")
        return {"error": "Database error"}


@app.get("/jobs/{job_id}/report")
async def download_report(job_id: str):
    """Generate analysis report for a job"""
    try:
        job = await db.job.find_unique(
            where={"id": job_id},
            include={"threats": True}
        )

        if not job:
            return {"error": "Job not found"}

        # Return report data (could be enhanced to generate PDF/formatted report)
        return {
            "job": job,
            "report_generated": True,
            "format": "json"
        }
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return {"error": "Report generation failed"}
