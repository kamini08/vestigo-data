import sys
import json
import os
import argparse
import shutil

# Import modules
from harvester import Harvester
from analyzer import FirmwareAnalyzer
from ingest import IngestionModule
from fs_scan import AdvancedLinuxAnalyzer

def main():
    parser = argparse.ArgumentParser(description="Vestigo-Omni Firmware Analysis Pipeline")
    parser.add_argument("firmware_file", help="Path to the firmware file")
    parser.add_argument("--workspace", default="./workspace", help="Workspace directory")
    args = parser.parse_args()

    target_file = os.path.abspath(args.firmware_file)
    if not os.path.exists(target_file):
        print(f"Error: File {target_file} not found.")
        sys.exit(1)

    target_file = sys.argv[1]
    
    # 1. Initialize & Run Module 1 (Ingestion)
    ingestor = IngestionModule()
    ingestion_report = ingestor.process(target_file)
    
    # 2. Check Routing Decision
    route = ingestion_report["routing"]["decision"]
    extracted_path = ingestion_report["extraction"].get("extracted_path")
    
    final_analysis = {}

    # 3. Dispatch to Specific Modules
    if route == "PATH_B_LINUX_FS":
        print("\n[+] Routing to Path B: Linux/FS Analyzer")
        analyzer = AdvancedLinuxAnalyzer()
        # We pass the folder where binwalk dumped the files
        final_analysis = analyzer.analyze(extracted_path)

    elif route == "PATH_A_BARE_METAL":
        print("\n[+] Routing to Path A: Bare Metal / ML Engine")
        analyzer = BareMetalAnalyzer()
        
        # For bare metal, we might need to find the largest .bin file in the extraction
        # Or pass the original file if extraction was partial.
        # For now, we pass the extraction root.
        final_analysis = analyzer.analyze(extracted_path)

    elif route == "PATH_C_HARD_TARGET":
        print("\n[+] Routing to Path C: Hard Target Analyzer")
        analyzer = HardTargetAnalyzer()
        # Hard targets usually failed extraction, so we pass the ORIGINAL file
        final_analysis = analyzer.analyze(target_file)

    print(f"[\u2699\ufe0f] Starting Vestigo-Omni Analysis on: {os.path.basename(target_file)}")
    
    # Initialize Modules
    ingest = IngestionModule(output_base_dir=args.workspace)
    harvester = Harvester(workspace_dir=args.workspace)
    fs_analyzer = AdvancedLinuxAnalyzer()
    bin_analyzer = FirmwareAnalyzer()

    # --- Phase 1: Ingestion & Identification ---
    print("\n--- Phase 1: Ingestion & Identification ---")
    # We use Ingest module's logic to identify the file type
    file_type = ingest._get_file_type(target_file)
    print(f"[\u2139\ufe0f] Identified File Type: {file_type}")

    # Decision: Is it a standalone binary or a firmware image?
    is_standalone = False
    if "ELF" in file_type and "executable" in file_type:
        is_standalone = True
        print("[\u2192] Routing: Detected standalone binary. Skipping extraction.")
    else:
        print("[\u2192] Routing: Detected potential firmware/container. Proceeding to extraction.")

    extracted_path = None
    binaries = []
    fs_report = None

    # --- Phase 2: Extraction (Harvester) ---
    if not is_standalone:
        print("\n--- Phase 2: Recursive Extraction (Harvester) ---")
        extracted_path = harvester.unpack_firmware(target_file)
        
        if extracted_path:
            # --- Phase 3: Filesystem Analysis (Module 2) ---
            # Check if it looks like a Linux FS
            if ingest._is_linux_fs(extracted_path):
                print("\n--- Phase 3: Linux Filesystem Analysis (Module 2) ---")
                print("[\u1f50d] Detected Linux Filesystem structure. Running Deep Scan...")
                fs_report = fs_analyzer.analyze(extracted_path)
            else:
                print("\n--- Phase 3: Filesystem Analysis ---")
                print("[\u2139\ufe0f] No Linux FS structure detected. Skipping FS Deep Scan.")

            # Find binaries for Phase 4
            binaries = harvester.find_binaries(extracted_path)
        else:
            print("[\u26a0\ufe0f] Extraction failed or produced no output.")
    else:
        # For standalone, the binary itself is the target
        binaries = [target_file]

    # --- Phase 4: Binary Analysis (Module 3) ---
    print("\n--- Phase 4: Binary Analysis (Module 3) ---")
    if binaries:
        print(f"[\u2699\ufe0f] Analyzing {len(binaries)} binaries...")
        analysis_results = bin_analyzer.process_binaries(binaries)
    else:
        print("[\u26a0\ufe0f] No binaries to analyze.")
        analysis_results = []

    # --- Phase 5: Reporting ---
    print("\n--- Phase 5: Reporting ---")
    report = {
        "File": os.path.basename(target_file),
        "FileType": file_type,
        "FileSystem": "Found (Extracted)" if extracted_path else "None/Standalone",
        "FS_Analysis": fs_report if fs_report else "Skipped",
        "Binaries": {}
    }

    for res in analysis_results:
        bin_path = res["file"]
        # Strip workspace path for readability
        rel_path = bin_path
        if args.workspace in bin_path:
             rel_path = bin_path.split(args.workspace)[1]
        elif extracted_path and extracted_path in bin_path:
             rel_path = bin_path.replace(extracted_path, "")

        entry = {
            "Status": res["status"],
            "Action": res.get("action", "None"),
        }
        
        if "static_analysis" in res:
            sa = res["static_analysis"]
            entry["Static Analysis"] = sa.get("gnn_classification", "Unknown")
            if sa.get("crypto_findings", {}).get("static_signatures"):
                 entry["Signatures"] = [x["algorithm"] for x in sa["crypto_findings"]["static_signatures"]]

        if "dynamic_result" in res:
            entry["Dynamic Result"] = res["dynamic_result"]

        report["Binaries"][rel_path] = entry

    # Save JSON
    output_filename = f"report_{os.path.basename(target_file)}.json"
    with open(output_filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[\u2705] Full Analysis Complete. Report saved to {output_filename}")
    
    # Print Text Summary
    print("\n\U0001f4ca The Resulting Data")
    print(f"    File: {report['File']}")
    print(f"        FileSystem: {report['FileSystem']}")
    if fs_report and fs_report != "Skipped":
        print(f"        Vulnerabilities: {len(fs_report.get('vulnerabilities', []))}")
    
    for i, (path, data) in enumerate(report["Binaries"].items(), 1):
        # Limit summary to first 10 binaries to avoid spamming console
        if i > 10:
            print(f"        ... and {len(report['Binaries']) - 10} more.")
            break
        print(f"        Binary {i}: {path}")
        print(f"            Status: {data['Status']}")
        if "Static Analysis" in data:
            print(f"            Static Analysis: {data['Static Analysis']}")
        if "Dynamic Result" in data:
            print(f"            Action: {data['Action']}")
            print(f"            Dynamic Result: {data['Dynamic Result']}")

if __name__ == "__main__":
    main()
