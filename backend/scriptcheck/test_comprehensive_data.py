#!/usr/bin/env python3
"""
Test script for comprehensive data collection functionality
"""

import json
import sys
import os
from pathlib import Path
from typing import Dict, Any

# Add current directory to path
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

def collect_job_analysis_data(job_id: str) -> Dict[str, Any]:
    """
    Collect all analysis data for a job including job storage, qiling output, 
    pipeline output, and any related child jobs.
    """
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
    pipeline_output_dir = Path("../pipeline_output")  # Relative to backend directory
    
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
            
            # Look for pipeline files matching this binary
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
                        else:  # CSV files
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
        
        # Look for child jobs (bootloader analysis jobs, crypto library jobs, etc.)
        # These would have references to the parent job in their job storage
        all_job_files = list(job_storage_dir.glob("*.json"))
        for job_file in all_job_files:
            if job_file.stem == job_id:  # Skip the main job
                continue
                
            try:
                with open(job_file, 'r') as f:
                    job_data = json.load(f)
                    
                # Check if this job references our parent job
                analysis_results = job_data.get("analysis_results", {})
                if analysis_results.get("parent_job_id") == job_id:
                    analysis_data["child_jobs"].append({
                        "job_id": job_file.stem,
                        "job_data": job_data
                    })
            except Exception as e:
                print(f"Warning: Failed to check job file {job_file} for parent reference: {e}")
        
        # Collect information about all related files
        analysis_data["related_files"] = {
            "job_storage_files": len([f for f in job_storage_dir.glob(f"{job_id}*")]),
            "qiling_output_files": len(qiling_files) if qiling_files else 0,
            "pipeline_output_files": len(pipeline_files) if 'pipeline_files' in locals() else 0,
            "child_job_count": len(analysis_data["child_jobs"])
        }
        
        print(f"Collected analysis data for job {job_id}: {analysis_data['related_files']}")
        
    except Exception as e:
        print(f"Error collecting analysis data for job {job_id}: {e}")
    
    return analysis_data

def main():
    """Test the comprehensive data collection with the existing job"""
    job_id = "f68a456d-df51-4978-b0d7-891ca6ba2f6d"
    
    print(f"Testing comprehensive data collection for job: {job_id}")
    print("=" * 60)
    
    data = collect_job_analysis_data(job_id)
    
    print("\n📊 ANALYSIS SUMMARY:")
    print(f"Job ID: {data['job_id']}")
    print(f"Job Storage Available: {'✅' if data['job_storage_data'] else '❌'}")
    print(f"Qiling Results Available: {'✅' if data['qiling_output'] else '❌'}")
    print(f"Pipeline Results Available: {'✅' if data['pipeline_output'] else '❌'}")
    print(f"Child Jobs Found: {len(data.get('child_jobs', []))}")
    
    if data['job_storage_data']:
        job_data = data['job_storage_data']
        print(f"\n📁 JOB STORAGE DATA:")
        print(f"  Filename: {job_data.get('filename', 'N/A')}")
        print(f"  Status: {job_data.get('status', 'N/A')}")
        print(f"  File Size: {job_data.get('file_size', 'N/A')} bytes")
        print(f"  Routing: {job_data.get('routing_decision', 'N/A')}")
        
        # Check for feature extraction results
        features = job_data.get('feature_extraction_results')
        if features:
            print(f"  ✅ Feature extraction completed")
            print(f"    Functions: {features.get('summary', {}).get('total_functions', 'N/A')}")
            print(f"    Crypto Functions: {features.get('summary', {}).get('crypto_functions', 'N/A')}")
            
            # Check for ML classification
            ml_results = features.get('ml_classification')
            if ml_results:
                print(f"    ✅ ML Classification completed")
                file_summary = ml_results.get('file_summary', {})
                print(f"      Status: {file_summary.get('file_status', 'N/A')}")
                print(f"      Crypto %: {file_summary.get('crypto_percentage', 'N/A')}%")
                detected_algos = file_summary.get('detected_algorithms', [])
                if detected_algos:
                    print(f"      Algorithms: {', '.join(detected_algos)}")
        
        # Check for Qiling results in job data
        qiling_job_data = job_data.get('qiling_dynamic_results')
        if qiling_job_data:
            print(f"  ✅ Qiling analysis in job storage")
            print(f"    Status: {qiling_job_data.get('status', 'N/A')}")
            verdict = qiling_job_data.get('verdict', {})
            print(f"    Crypto Detected: {verdict.get('crypto_detected', 'N/A')}")
            print(f"    Confidence: {verdict.get('confidence', 'N/A')}")
    
    if data['qiling_output']:
        print(f"\n🔍 QILING OUTPUT FILES:")
        for i, qiling_file in enumerate(data['qiling_output']):
            print(f"  {i+1}. {qiling_file['filename']}")
            qiling_data = qiling_file['data']
            print(f"     Status: {qiling_data.get('status', 'N/A')}")
            verdict = qiling_data.get('verdict', {})
            print(f"     Crypto Detected: {verdict.get('crypto_detected', 'N/A')}")
    
    if data['pipeline_output']:
        print(f"\n🔧 PIPELINE OUTPUT FILES:")
        for i, pipeline_file in enumerate(data['pipeline_output']):
            print(f"  {i+1}. {pipeline_file['filename']} ({pipeline_file['type']})")
    
    print(f"\n📈 RELATED FILES SUMMARY:")
    related = data['related_files']
    print(f"  Job Storage Files: {related.get('job_storage_files', 0)}")
    print(f"  Qiling Output Files: {related.get('qiling_output_files', 0)}")
    print(f"  Pipeline Output Files: {related.get('pipeline_output_files', 0)}")
    print(f"  Child Jobs: {related.get('child_job_count', 0)}")
    
    print("\n" + "=" * 60)
    print("✅ Comprehensive data collection test completed!")
    
    return data

if __name__ == "__main__":
    main()