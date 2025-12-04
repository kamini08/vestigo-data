#!/usr/bin/env python3
"""
Automatic Binary Unpacker
Detects and unpacks common packers (UPX, Themida, VMProtect, etc.)
"""

import subprocess
import os
import tempfile
import shutil
from pathlib import Path

class BinaryUnpacker:
    """
    Automatic unpacker for packed binaries.
    Supports UPX and detects other common packers.
    """
    
    SUPPORTED_PACKERS = {
        'UPX': {
            'signatures': [b'UPX!', b'UPX0', b'UPX1', b'UPX2'],
            'strings': ['upx', '$Id: UPX'],
            'unpack_cmd': ['upx', '-d', '{input}', '-o', '{output}'],
            'available': None  # Will check on first use
        },
        'Themida': {
            'signatures': [b'Themida', b'WinLicense'],
            'strings': ['Themida', 'Oreans'],
            'unpack_cmd': None,  # Requires specialized tools
            'available': False
        },
        'VMProtect': {
            'signatures': [b'VMProtect', b'.vmp0', b'.vmp1'],
            'strings': ['VMProtect'],
            'unpack_cmd': None,  # Requires specialized tools
            'available': False
        },
        'ASPack': {
            'signatures': [b'aPLib', b'.aspack'],
            'strings': ['ASPack'],
            'unpack_cmd': None,
            'available': False
        }
    }
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix='unpacked_')
        self._check_upx_available()
    
    def _check_upx_available(self):
        """Check if UPX is installed"""
        try:
            result = subprocess.run(
                ['upx', '--version'],
                capture_output=True,
                timeout=5
            )
            self.SUPPORTED_PACKERS['UPX']['available'] = (result.returncode == 0)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.SUPPORTED_PACKERS['UPX']['available'] = False
    
    def detect_packer(self, binary_path: str) -> tuple:
        """
        Detect which packer was used.
        
        Returns:
            (packer_name, confidence) or (None, 0) if not packed
        """
        try:
            with open(binary_path, 'rb') as f:
                # Read first 8KB and last 8KB (packers often leave signatures)
                header = f.read(8192)
                f.seek(-8192, 2)  # Seek to 8KB before end
                footer = f.read(8192)
                data = header + footer
        except Exception as e:
            print(f"[!] Error reading binary: {e}")
            return (None, 0)
        
        detected = []
        
        for packer_name, info in self.SUPPORTED_PACKERS.items():
            confidence = 0
            
            # Check binary signatures
            for signature in info['signatures']:
                if signature in data:
                    confidence += 50
                    break
            
            # Check for string markers
            for string_marker in info['strings']:
                if string_marker.encode() in data:
                    confidence += 30
                    break
            
            if confidence > 0:
                detected.append((packer_name, confidence))
        
        if detected:
            # Return packer with highest confidence
            detected.sort(key=lambda x: x[1], reverse=True)
            return detected[0]
        
        return (None, 0)
    
    def unpack(self, binary_path: str, force=False) -> tuple:
        """
        Try to unpack binary.
        
        Args:
            binary_path: Path to potentially packed binary
            force: Force unpacking attempt even if packer not detected
        
        Returns:
            (unpacked_path, success, packer_name)
            - unpacked_path: Path to unpacked binary (or original if failed)
            - success: True if unpacking succeeded
            - packer_name: Name of detected packer or None
        """
        
        if not os.path.exists(binary_path):
            print(f"[!] Binary not found: {binary_path}")
            return (binary_path, False, None)
        
        # Detect packer
        packer_name, confidence = self.detect_packer(binary_path)
        
        if not packer_name:
            if not force:
                return (binary_path, False, None)
            else:
                print("[*] No packer detected, but forcing unpack attempt...")
                packer_name = 'UPX'  # Try UPX by default
        
        print(f"[+] Detected packer: {packer_name} (confidence: {confidence}%)")
        
        packer_info = self.SUPPORTED_PACKERS[packer_name]
        
        # Check if unpacker is available
        if not packer_info.get('available'):
            if packer_info['unpack_cmd'] is None:
                print(f"[!] {packer_name} unpacking not supported")
                print(f"    This packer requires specialized tools.")
                print(f"    Attempting to analyze packed binary as-is...")
                return (binary_path, False, packer_name)
            else:
                print(f"[!] UPX not installed. Install with: sudo apt install upx-ucl")
                return (binary_path, False, packer_name)
        
        # Try to unpack
        output_path = os.path.join(
            self.temp_dir,
            'unpacked_' + os.path.basename(binary_path)
        )
        
        cmd = [
            arg.format(input=binary_path, output=output_path)
            for arg in packer_info['unpack_cmd']
        ]
        
        try:
            print(f"[*] Unpacking with: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=60,
                text=True
            )
            
            if result.returncode == 0 and os.path.exists(output_path):
                # Verify unpacked file is valid
                file_size = os.path.getsize(output_path)
                if file_size > 0:
                    print(f"[✓] Successfully unpacked to: {output_path}")
                    print(f"    Original size: {os.path.getsize(binary_path)} bytes")
                    print(f"    Unpacked size: {file_size} bytes")
                    return (output_path, True, packer_name)
                else:
                    print(f"[!] Unpacked file is empty")
                    return (binary_path, False, packer_name)
            else:
                stderr = result.stderr if result.stderr else "No error message"
                print(f"[!] Unpacking failed: {stderr}")
                
                # Some UPX variants fail with standard unpacking
                # Try alternative methods
                if packer_name == 'UPX':
                    print("[*] Trying alternative UPX unpacking methods...")
                    success = self._unpack_upx_alternative(binary_path, output_path)
                    if success:
                        return (output_path, True, packer_name)
                
                return (binary_path, False, packer_name)
        
        except subprocess.TimeoutExpired:
            print(f"[!] Unpacking timed out (>60s)")
            return (binary_path, False, packer_name)
        
        except Exception as e:
            print(f"[!] Unpacking error: {e}")
            return (binary_path, False, packer_name)
    
    def _unpack_upx_alternative(self, binary_path: str, output_path: str) -> bool:
        """
        Alternative UPX unpacking methods for modified/corrupted UPX.
        """
        
        # Method 1: Force decompression
        try:
            cmd = ['upx', '-d', '--force', binary_path, '-o', output_path]
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            
            if result.returncode == 0 and os.path.exists(output_path):
                print("[✓] Alternative method succeeded (--force)")
                return True
        except:
            pass
        
        # Method 2: Ignore broken sections
        try:
            cmd = ['upx', '-d', '--force-overwrite', binary_path, '-o', output_path]
            result = subprocess.run(cmd, capture_output=True, timeout=60)
            
            if result.returncode == 0 and os.path.exists(output_path):
                print("[✓] Alternative method succeeded (--force-overwrite)")
                return True
        except:
            pass
        
        return False
    
    def cleanup(self):
        """Clean up temporary directory"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(f"[!] Cleanup error: {e}")
    
    def __del__(self):
        """Destructor - clean up temp files"""
        self.cleanup()


def main():
    """CLI interface for unpacker"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 unpacker.py <binary_path>")
        print("\nAutomatic binary unpacker for packed executables.")
        print("Supports: UPX (auto-unpack), Themida, VMProtect (detect only)")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    if not os.path.exists(binary_path):
        print(f"[-] Error: File not found: {binary_path}")
        sys.exit(1)
    
    print(f"[*] Analyzing: {binary_path}")
    print(f"[*] File size: {os.path.getsize(binary_path) / 1024:.2f} KB")
    print()
    
    unpacker = BinaryUnpacker()
    
    # Detect packer
    packer_name, confidence = unpacker.detect_packer(binary_path)
    
    if packer_name:
        print(f"[+] Packer detected: {packer_name} ({confidence}% confidence)")
    else:
        print("[-] No packer detected (or unknown packer)")
        sys.exit(0)
    
    # Try to unpack
    print()
    unpacked_path, success, _ = unpacker.unpack(binary_path)
    
    if success:
        print()
        print(f"[✓] Unpacking successful!")
        print(f"[*] Unpacked binary: {unpacked_path}")
        print()
        print("You can now analyze the unpacked binary with verify_crypto.py")
    else:
        print()
        print(f"[!] Unpacking failed or not supported")
        print(f"[*] You can still analyze the packed binary, but results may be limited")


if __name__ == '__main__':
    main()
