#!/usr/bin/env python3
"""
Kaspersky Quarantine File Decryptor

This script decrypts files that were quarantined by Kaspersky antivirus.
Quarantined files are XOR-encrypted and stored in a specific folder.
"""

import sys
import os
from pathlib import Path


def print_usage():
    """Display usage information and exit."""
    print("Usage:   python3 dexor_QB.py <folder_with_kasper_files> <folder_to_save_output>")
    print("Example: python3 dexor_QB.py \"C:\\ProgramData\\Kaspersky Lab\\KES\\QB\\\" \"C:\\output\\\"")
    sys.exit(0)


def decrypt_file(input_path: Path, output_path: Path) -> bool:
    """
    Decrypt a single Kaspersky quarantined file.
    
    Args:
        input_path: Path to the encrypted input file
        output_path: Path where the decrypted file will be saved
        
    Returns:
        True if decryption was successful, False otherwise
    """
    # Kaspersky XOR decryption key (8 bytes)
    xor_key = bytes([0xe2, 0x45, 0x48, 0xec, 0x69, 0x0e, 0x5c, 0xac])
    key_length = len(xor_key)
    
    try:
        file_size = input_path.stat().st_size
        
        # Skip the first 64 bytes (Kaspersky header)
        header_size = 64
        if file_size < header_size:
            print(f"  Error: File too small (less than {header_size} bytes)")
            return False
        
        encrypted_size = file_size - header_size
        
        with open(input_path, "rb") as in_file, open(output_path, "wb") as out_file:
            # Skip the header
            in_file.seek(header_size)
            
            # Read and decrypt the rest of the file
            bytes_read = 0
            while bytes_read < encrypted_size:
                byte = in_file.read(1)
                if not byte:
                    break
                
                # XOR decrypt using the key (cycling through key bytes)
                key_byte = xor_key[bytes_read % key_length]
                decrypted_byte = bytes([byte[0] ^ key_byte])
                out_file.write(decrypted_byte)
                bytes_read += 1
        
        print(f"  Successfully decrypted {bytes_read} bytes")
        return True
        
    except Exception as e:
        print(f"  Error processing file: {e}")
        return False


def decrypt_quarantine_files(input_directory: Path, output_directory: Path):
    """
    Decrypt all files in the Kaspersky quarantine directory.
    
    Args:
        input_directory: Directory containing encrypted quarantine files
        output_directory: Directory where decrypted files will be saved
    """
    if not input_directory.exists():
        print(f"Error: Input directory does not exist: {input_directory}")
        sys.exit(1)
    
    if not input_directory.is_dir():
        print(f"Error: Input path is not a directory: {input_directory}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    output_directory.mkdir(parents=True, exist_ok=True)
    
    # Process all files in the input directory
    files_processed = 0
    files_successful = 0
    
    for filename in os.listdir(input_directory):
        input_path = input_directory / filename
        
        # Skip directories
        if input_path.is_dir():
            continue
        
        files_processed += 1
        output_filename = f"{filename}_decrypted"
        output_path = output_directory / output_filename
        
        print(f"\nProcessing: {filename}")
        if decrypt_file(input_path, output_path):
            files_successful += 1
    
    print(f"\n{'='*60}")
    print(f"Summary: {files_successful}/{files_processed} files successfully decrypted")
    print(f"{'='*60}")


def main():
    """Main entry point."""
    if len(sys.argv) < 3:
        print_usage()
    
    input_dir = Path(sys.argv[1])
    output_dir = Path(sys.argv[2])
    
    # Normalize paths (ensure they end with separator for display)
    if not str(input_dir).endswith(os.sep):
        input_dir = Path(str(input_dir) + os.sep)
    if not str(output_dir).endswith(os.sep):
        output_dir = Path(str(output_dir) + os.sep)
    
    decrypt_quarantine_files(input_dir, output_dir)


if __name__ == "__main__":
    main()
