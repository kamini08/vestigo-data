"""
Binary Converter Service for Vestigo Backend
Converts object files (.o) to executable ELF files (.elf)
"""

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Tuple
from config.logging_config import logger


class BinaryConverterService:
    """
    Service for converting object files to executable binaries.
    
    This service:
    1. Detects architecture from .o file
    2. Uses appropriate linker (ld) to create executable
    3. Validates the output ELF file
    """
    
    def __init__(self):
        logger.info("BinaryConverterService initialized")
    
    def convert_object_to_elf(self, object_file_path: str, output_dir: Optional[str] = None) -> Optional[str]:
        """
        Convert a .o (object file) to .elf (executable)
        
        Args:
            object_file_path: Path to the .o file
            output_dir: Directory to save the .elf file (defaults to same dir as input)
            
        Returns:
            Path to the generated .elf file, or None if conversion failed
        """
        if not os.path.exists(object_file_path):
            logger.error(f"Object file not found: {object_file_path}")
            return None
        
        if not object_file_path.endswith('.o'):
            logger.warning(f"File does not have .o extension: {object_file_path}")
        
        # Determine output path
        if output_dir is None:
            output_dir = os.path.dirname(object_file_path)
        
        base_name = os.path.splitext(os.path.basename(object_file_path))[0]
        output_elf_path = os.path.join(output_dir, f"{base_name}.elf")
        
        logger.info(f"Converting .o to .elf: {object_file_path} -> {output_elf_path}")
        
        # Detect architecture
        arch_info = self._detect_architecture(object_file_path)
        if not arch_info:
            logger.error(f"Failed to detect architecture for: {object_file_path}")
            return None
        
        logger.info(f"Detected architecture: {arch_info['arch']} ({arch_info['bits']}-bit)")
        
        # Try to link the object file
        success = self._link_object_file(object_file_path, output_elf_path, arch_info)
        
        if success and os.path.exists(output_elf_path):
            # Verify it's a valid ELF
            if self._is_valid_elf(output_elf_path):
                logger.info(f"Successfully converted to ELF: {output_elf_path}")
                return output_elf_path
            else:
                logger.error(f"Generated file is not a valid ELF: {output_elf_path}")
                return None
        else:
            logger.error(f"Failed to convert .o to .elf: {object_file_path}")
            return None
    
    def _detect_architecture(self, object_file_path: str) -> Optional[dict]:
        """
        Detect architecture of object file using readelf or file command
        
        Returns:
            Dict with 'arch' (x86_64, ARM, MIPS, etc.) and 'bits' (32 or 64)
        """
        try:
            # Try readelf first (more detailed)
            result = subprocess.run(
                ['readelf', '-h', object_file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse machine type
                arch_info = {
                    'arch': 'unknown',
                    'bits': 32,
                    'endian': 'little'
                }
                
                # Detect architecture
                if 'X86-64' in output or 'x86-64' in output:
                    arch_info['arch'] = 'x86_64'
                    arch_info['bits'] = 64
                elif 'Intel 80386' in output or 'i386' in output:
                    arch_info['arch'] = 'x86'
                    arch_info['bits'] = 32
                elif 'ARM' in output or 'AArch64' in output:
                    if 'AArch64' in output:
                        arch_info['arch'] = 'aarch64'
                        arch_info['bits'] = 64
                    else:
                        arch_info['arch'] = 'arm'
                        arch_info['bits'] = 32
                elif 'MIPS' in output:
                    arch_info['arch'] = 'mips'
                    arch_info['bits'] = 64 if 'MIPS64' in output else 32
                
                # Detect endianness
                if 'LSB' in output or "2's complement, little endian" in output:
                    arch_info['endian'] = 'little'
                elif 'MSB' in output or "2's complement, big endian" in output:
                    arch_info['endian'] = 'big'
                
                return arch_info
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"readelf failed: {e}, trying file command")
        
        try:
            # Fallback to file command
            result = subprocess.run(
                ['file', object_file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout.lower()
                
                arch_info = {
                    'arch': 'unknown',
                    'bits': 32,
                    'endian': 'little'
                }
                
                # Simple parsing
                if 'x86-64' in output or 'x86_64' in output:
                    arch_info['arch'] = 'x86_64'
                    arch_info['bits'] = 64
                elif 'intel 80386' in output or 'i386' in output:
                    arch_info['arch'] = 'x86'
                    arch_info['bits'] = 32
                elif 'arm' in output:
                    arch_info['arch'] = 'arm'
                    arch_info['bits'] = 64 if 'aarch64' in output else 32
                elif 'mips' in output:
                    arch_info['arch'] = 'mips'
                    arch_info['bits'] = 32
                
                if 'lsb' in output:
                    arch_info['endian'] = 'little'
                elif 'msb' in output:
                    arch_info['endian'] = 'big'
                
                return arch_info
                
        except Exception as e:
            logger.error(f"Architecture detection failed: {e}")
        
        return None
    
    def _link_object_file(self, object_path: str, output_path: str, arch_info: dict) -> bool:
        """
        Link object file to create executable ELF
        
        Uses appropriate linker based on architecture
        """
        # Select linker based on architecture
        linker = self._get_linker_command(arch_info['arch'])
        
        if not linker:
            logger.error(f"No linker available for architecture: {arch_info['arch']}")
            logger.info(f"Skipping .o to .elf conversion. Qiling will attempt to analyze the .o file directly.")
            return False
        
        try:
            # Basic linking command
            # We create a simple executable without complex runtime setup
            cmd = [
                linker,
                '-o', output_path,
                object_path,
                '--entry=0',  # Use address 0 as entry (will be adjusted by dynamic analysis)
                '-nostdlib'   # Don't link with standard libraries
            ]
            
            logger.debug(f"Linking command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"Linking successful: {output_path}")
                return True
            else:
                # Try alternative approach: create minimal ELF wrapper
                logger.warning(f"Standard linking failed: {result.stderr.strip()[:200]}")
                logger.info("Attempting alternative conversion method...")
                return self._create_minimal_elf_wrapper(object_path, output_path, arch_info, linker)
                
        except subprocess.TimeoutExpired:
            logger.error("Linking timed out")
            return False
        except FileNotFoundError:
            logger.error(f"Linker not found: {linker}")
            return False
        except Exception as e:
            logger.error(f"Linking failed: {e}")
            return False
    
    def _create_minimal_elf_wrapper(self, object_path: str, output_path: str, arch_info: dict, linker: str) -> bool:
        """
        Create a minimal ELF executable by copying the object file with ELF header adjustments
        
        For Qiling analysis, we just need a loadable ELF format
        """
        try:
            # Try using ld with relaxed options for relocatable output
            cmd = [
                linker,
                '-r',  # Relocatable output (keeps all symbols and relocation info)
                '-o', output_path,
                object_path
            ]
            
            logger.debug(f"Attempting relocatable link: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"Created relocatable ELF: {output_path}")
                return True
            else:
                logger.error(f"Minimal ELF creation failed: {result.stderr.strip()[:200]}")
                
                # Final fallback: Just copy the .o file as-is
                # Qiling can sometimes work with bare object files
                logger.info("Copying object file as-is for Qiling analysis")
                import shutil
                shutil.copy(object_path, output_path)
                return True
                
        except Exception as e:
            logger.error(f"Minimal ELF wrapper creation failed: {e}")
            return False
    
    def _get_linker_command(self, arch: str) -> Optional[str]:
        """
        Get the appropriate linker command for the architecture
        """
        # Map architecture to linker (prioritize cross-compiler toolchains)
        linker_candidates = {
            'x86_64': ['ld', 'x86_64-linux-gnu-ld'],
            'x86': ['ld', 'i686-linux-gnu-ld'],
            'arm': ['arm-linux-gnueabi-ld', 'arm-linux-gnueabihf-ld', 'arm-none-eabi-ld'],
            'aarch64': ['aarch64-linux-gnu-ld', 'aarch64-none-elf-ld', 'aarch64-elf-ld'],
            'mips': ['mips-linux-gnu-ld', 'mips-elf-ld'],
            'mipsel': ['mipsel-linux-gnu-ld', 'mipsel-elf-ld']
        }
        
        # Get candidates for this architecture
        candidates = linker_candidates.get(arch, ['ld'])
        
        # Try each candidate linker
        for linker in candidates:
            try:
                result = subprocess.run(['which', linker], capture_output=True, timeout=5)
                if result.returncode == 0:
                    logger.info(f"Found linker for {arch}: {linker}")
                    return linker
            except:
                continue
        
        # If no arch-specific linker found, warn and return None
        logger.warning(f"No suitable linker found for {arch}. Consider installing cross-compiler toolchain.")
        logger.warning(f"  For ARM64: sudo apt install binutils-aarch64-linux-gnu")
        logger.warning(f"  For ARM32: sudo apt install binutils-arm-linux-gnueabi")
        logger.warning(f"  For MIPS: sudo apt install binutils-mips-linux-gnu")
        
        return None
    
    def _is_valid_elf(self, file_path: str) -> bool:
        """
        Check if file is a valid ELF binary
        """
        if not os.path.exists(file_path):
            return False
        
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                return magic == b'\x7fELF'
        except Exception as e:
            logger.error(f"Error checking ELF magic: {e}")
            return False
    
    def is_object_file(self, file_path: str) -> bool:
        """
        Check if file is an object file (.o) or relocatable file
        
        Returns True if it's a relocatable ELF (object file)
        This includes .o files and some .so files that are relocatable
        """
        if not os.path.exists(file_path):
            return False
        
        # Check extension - .o files are always object files
        if file_path.endswith('.o'):
            return True
        
        # Check ELF type using readelf
        try:
            result = subprocess.run(
                ['readelf', '-h', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                output = result.stdout
                # Look for "Type: REL (Relocatable file)"
                if 'REL (Relocatable file)' in output or 'Type:.*REL' in output:
                    logger.debug(f"Detected relocatable object file: {file_path}")
                    return True
                    
        except Exception as e:
            logger.debug(f"readelf check failed: {e}")
        
        return False
    
    def needs_conversion(self, file_path: str) -> bool:
        """
        Check if a file needs conversion to be analyzed by Qiling
        
        Returns True if:
        - It's an object file (.o)
        - It's a relocatable ELF that's not executable
        - It's a shared object that might benefit from conversion
        """
        if not os.path.exists(file_path):
            return False
        
        # .o files always need conversion
        if file_path.endswith('.o'):
            return True
        
        # Check if it's relocatable
        if self.is_object_file(file_path):
            return True
        
        # .so files that are DYN (shared object) don't need conversion
        # They can be analyzed directly by Qiling
        return False
