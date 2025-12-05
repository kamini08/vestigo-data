import os
import subprocess
import tempfile
import shutil
from typing import Dict, List, Any


class CryptoLibraryService:
    """
    Service to handle .so and .a library files found in extracted firmware.
    
    - .so files: Shared objects are ELF binaries - sent DIRECTLY to Ghidra for disassembly
                 Cannot be "extracted" (they're already compiled), analyzed as-is
    - .a files: Static archives - EXTRACTED using 'ar x' to get individual .o files
                Each .o file is then sent separately to Ghidra for analysis
    """
    
    def __init__(self):
        pass
    
    def process_crypto_libraries(self, crypto_libs: Dict[str, List[Dict]], job_id: str) -> Dict[str, Any]:
        """
        Process discovered libraries from firmware extraction.
        
        Args:
            crypto_libs: Dict with 'so_files' and 'a_files' lists
            job_id: Parent job ID for tracking
            
        Returns:
            Processing results with details for each library
            
        Processing flow:
            .so files → Direct PATH_A analysis (they're ELF binaries)
            .a files → Extract to .o files → Each .o to PATH_A analysis
        """
        results = {
            "job_id": job_id,
            "so_files_processed": [],
            "a_files_processed": [],
            "extracted_objects": [],
            "status": "processing"
        }
        
        # Process .so files (shared objects)
        for so_file in crypto_libs.get('so_files', []):
            so_result = self._process_shared_object(so_file, job_id)
            results["so_files_processed"].append(so_result)
        
        # Process .a files (static archives)
        for a_file in crypto_libs.get('a_files', []):
            a_result = self._process_static_archive(a_file, job_id)
            results["a_files_processed"].append(a_result)
            
            # If we extracted .o files, add them to the list
            if a_result.get('extracted_objects'):
                results["extracted_objects"].extend(a_result['extracted_objects'])
        
        results["status"] = "complete"
        results["summary"] = {
            "total_so_files": len(results["so_files_processed"]),
            "total_a_files": len(results["a_files_processed"]),
            "total_extracted_objects": len(results["extracted_objects"])
        }
        
        return results
    
    def _process_shared_object(self, so_file: Dict, job_id: str) -> Dict[str, Any]:
        """
        Process a .so (shared object) file.
        
        .so files are ELF shared libraries - they're already compiled binaries.
        We send them DIRECTLY to Ghidra for disassembly/decompilation.
        
        Think of it like: .a → extract .o files → analyze each .o
                         .so → analyze directly (it's already a binary)
        
        Returns metadata for PATH_A pipeline processing.
        """
        result = {
            "file": so_file["file"],
            "path": so_file["path"],
            "size": so_file["size"],
            "type": "shared_object",
            "status": "ready_for_analysis",
            "pipeline": "PATH_A_BARE_METAL",
            "analysis_type": "direct_binary_analysis"
        }
        
        # Check if file exists and is readable
        if not os.path.exists(so_file["path"]):
            result["status"] = "error"
            result["error"] = "File not found"
            return result
        
        # Get basic file info
        try:
            file_type = subprocess.run(
                ["file", so_file["path"]],
                capture_output=True,
                text=True,
                timeout=5
            )
            result["file_type"] = file_type.stdout.strip()
        except:
            result["file_type"] = "unknown"
        
        return result
    
    def _process_static_archive(self, a_file: Dict, job_id: str) -> Dict[str, Any]:
        """
        Process a .a (static archive) file by extracting .o files.
        Each .o file will be sent to PATH_A pipeline.
        
        Returns extraction results with list of .o files.
        """
        result = {
            "file": a_file["file"],
            "path": a_file["path"],
            "size": a_file["size"],
            "type": "static_archive",
            "status": "processing",
            "extracted_objects": []
        }
        
        # Check if file exists
        if not os.path.exists(a_file["path"]):
            result["status"] = "error"
            result["error"] = "File not found"
            return result
        
        # Create temporary extraction directory
        temp_dir = tempfile.mkdtemp(prefix=f"ar_extract_{job_id}_")
        
        try:
            # Use 'ar' command to extract .o files
            # ar x archive.a - extracts all files from archive
            extract_result = subprocess.run(
                ["ar", "x", a_file["path"]],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if extract_result.returncode != 0:
                result["status"] = "error"
                result["error"] = f"ar extraction failed: {extract_result.stderr}"
                shutil.rmtree(temp_dir)
                return result
            
            # List extracted .o files
            extracted_files = []
            for filename in os.listdir(temp_dir):
                if filename.endswith('.o'):
                    full_path = os.path.join(temp_dir, filename)
                    file_size = os.path.getsize(full_path)
                    
                    extracted_files.append({
                        "file": filename,
                        "path": full_path,
                        "size": file_size,
                        "parent_archive": a_file["file"],
                        "pipeline": "PATH_A_BARE_METAL",
                        "analysis_type": "object_file_analysis"
                    })
            
            result["extracted_objects"] = extracted_files
            result["extraction_dir"] = temp_dir
            result["status"] = "extracted"
            result["extracted_count"] = len(extracted_files)
            
            print(f"    ⇥ Extracted {len(extracted_files)} .o files from {a_file['file']}")
            
        except subprocess.TimeoutExpired:
            result["status"] = "error"
            result["error"] = "Extraction timeout"
            shutil.rmtree(temp_dir)
        except FileNotFoundError:
            result["status"] = "error"
            result["error"] = "ar command not found - install binutils"
            shutil.rmtree(temp_dir)
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            shutil.rmtree(temp_dir)
        
        return result
    
    def get_objects_for_pipeline(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get list of all files ready for PATH_A pipeline processing.
        Includes both .so files and extracted .o files from .a archives.
        
        Returns:
            List of file dicts ready for bare metal analysis
        """
        pipeline_files = []
        
        # Add .so files (analyzed directly)
        for so_file in results.get("so_files_processed", []):
            if so_file.get("status") == "ready_for_analysis":
                pipeline_files.append(so_file)
        
        # Add extracted .o files from .a archives
        pipeline_files.extend(results.get("extracted_objects", []))
        
        return pipeline_files
