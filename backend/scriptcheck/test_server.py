#!/usr/bin/env python3
"""
Simplified test server to test the comprehensive analyze endpoint
"""

import json
import time
import sys
from pathlib import Path
from typing import Dict, Any

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="Vestigo Test Backend")

# CORS
origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def collect_job_analysis_data(job_id: str) -> Dict[str, Any]:
    """Collect all analysis data for a job"""
    analysis_data = {
        "job_id": job_id,
        "job_storage_data": None,
        "qiling_output": None,
        "pipeline_output": None,
        "child_jobs": [],
        "related_files": []
    }
    
    # Paths for different output locations
    job_storage_dir = Path("job_storage")
    qiling_output_dir = Path("qiling_output") 
    pipeline_output_dir = Path("../pipeline_output")
    
    try:
        # Load job storage data
        job_storage_file = job_storage_dir / f"{job_id}.json"
        if job_storage_file.exists():
            with open(job_storage_file, 'r') as f:
                analysis_data["job_storage_data"] = json.load(f)
        
        # Find qiling output files
        qiling_files = list(qiling_output_dir.glob(f"{job_id}_*.json"))
        if qiling_files:
            qiling_data = []
            for qiling_file in qiling_files:
                try:
                    with open(qiling_file, 'r') as f:
                        qiling_content = json.load(f)
                        qiling_data.append({
                            "filename": qiling_file.name,
                            "data": qiling_content
                        })
                except Exception as e:
                    print(f"Warning: Failed to load qiling file {qiling_file}: {e}")
            analysis_data["qiling_output"] = qiling_data
        
        # Find pipeline output files  
        if analysis_data["job_storage_data"]:
            filename = analysis_data["job_storage_data"].get("filename", "")
            binary_name = filename.split('.')[0] if filename else ""
            
            pipeline_files = []
            for pattern in [f"*{binary_name}*_pipeline.json", f"*{binary_name}*_pipeline_features.csv"]:
                pipeline_files.extend(list(pipeline_output_dir.glob(pattern)))
            
            if pipeline_files:
                pipeline_data = []
                for pipeline_file in pipeline_files:
                    try:
                        if pipeline_file.suffix == '.json':
                            with open(pipeline_file, 'r') as f:
                                content = json.load(f)
                        else:
                            with open(pipeline_file, 'r') as f:
                                content = f.read()
                        
                        pipeline_data.append({
                            "filename": pipeline_file.name,
                            "type": "json" if pipeline_file.suffix == '.json' else "csv", 
                            "data": content
                        })
                    except Exception as e:
                        print(f"Warning: Failed to load pipeline file {pipeline_file}: {e}")
                
                analysis_data["pipeline_output"] = pipeline_data
        
        # Collect information about related files
        analysis_data["related_files"] = {
            "job_storage_files": len([f for f in job_storage_dir.glob(f"{job_id}*")]),
            "qiling_output_files": len(qiling_files) if qiling_files else 0,
            "pipeline_output_files": len(pipeline_files) if 'pipeline_files' in locals() else 0,
            "child_job_count": 0
        }
        
    except Exception as e:
        print(f"Error collecting analysis data for job {job_id}: {e}")
    
    return analysis_data

@app.get("/")
def home():
    return {"message": "Vestigo Test Backend Running"}

@app.post("/analyze")
async def analyze_comprehensive(file: UploadFile = File(...)):
    """Test endpoint that returns comprehensive analysis data"""
    try:
        if file is None:
            raise HTTPException(status_code=400, detail="No file provided")

        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Empty file uploaded")

        print(f"Processing file: {file.filename} ({len(content)} bytes)")
        
        # For this test, use the existing job ID
        job_id = "f68a456d-df51-4978-b0d7-891ca6ba2f6d"
        
        # Simulate basic analysis result
        analysis_result = {
            "jobId": job_id,
            "fileName": file.filename,
            "fileSize": f"{len(content) / 1024:.2f} KB",
            "fileSizeBytes": len(content),
            "status": "analyzed",
            "analysis": {
                "routing_decision": "PATH_A_BARE_METAL",
                "routing_reason": "Input is an object file (.o) - routing to bare metal analysis.",
                "file_type": "ELF 64-bit LSB relocatable, ARM aarch64",
                "extraction_success": False,
                "workspace_path": f"/analysis_workspace/{file.filename}_analysis"
            }
        }
        
        # Collect comprehensive analysis data
        complete_analysis_data = collect_job_analysis_data(job_id)
        
        # Create enhanced response
        enhanced_response = {
            **analysis_result,
            "comprehensive_data": complete_analysis_data,
            "data_collection": {
                "job_storage_available": complete_analysis_data["job_storage_data"] is not None,
                "qiling_results_available": complete_analysis_data["qiling_output"] is not None,
                "pipeline_results_available": complete_analysis_data["pipeline_output"] is not None,
                "child_jobs_count": len(complete_analysis_data.get("child_jobs", [])),
                "collection_timestamp": time.time()
            }
        }
        
        print(f"✅ Analysis complete with comprehensive data")
        print(f"   Job Storage: {'✅' if complete_analysis_data['job_storage_data'] else '❌'}")
        print(f"   Qiling Results: {'✅' if complete_analysis_data['qiling_output'] else '❌'}")
        print(f"   Pipeline Results: {'✅' if complete_analysis_data['pipeline_output'] else '❌'}")
        
        return enhanced_response

    except HTTPException:
        raise
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/job/{job_id}/complete-analysis")
async def get_complete_analysis_data(job_id: str):
    """Get comprehensive analysis data for a job"""
    try:
        complete_data = collect_job_analysis_data(job_id)
        
        if not complete_data["job_storage_data"]:
            raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
        
        # Add summary statistics
        complete_data["summary"] = {
            "total_analysis_files": (
                (1 if complete_data["job_storage_data"] else 0) +
                len(complete_data.get("qiling_output", [])) +
                len(complete_data.get("pipeline_output", [])) +
                len(complete_data.get("child_jobs", []))
            ),
            "has_feature_extraction": bool(
                complete_data["job_storage_data"] and 
                complete_data["job_storage_data"].get("feature_extraction_results")
            ),
            "has_ml_classification": bool(
                complete_data["job_storage_data"] and 
                complete_data["job_storage_data"].get("feature_extraction_results", {}).get("ml_classification")
            ),
            "has_qiling_analysis": bool(complete_data.get("qiling_output")),
        }
        
        return complete_data
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Failed to get complete analysis data for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get complete analysis data: {str(e)}")

if __name__ == "__main__":
    print("🚀 Starting Vestigo Test Server...")
    print("📡 Available endpoints:")
    print("   POST /analyze - Upload file and get comprehensive analysis")
    print("   GET /job/{job_id}/complete-analysis - Get complete analysis data")
    print("🌐 Server will run on http://localhost:8000")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)