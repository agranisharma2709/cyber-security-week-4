import os
import hashlib
import requests
import concurrent.futures
import time

LOG_FILE = "scan_log.txt"

def log_to_file(message, filename="scan_log.txt"):
    """Log messages to a file using UTF-8 encoding to avoid Unicode errors."""
    with open(filename, "a", encoding="utf-8") as log:
        log.write(message + "\n")


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return f"Error reading file: {e}"

def check_virustotal(api_key, file_hash):
    """Check file hash on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            result = f"🚨 Malicious ({malicious_count} detections)" if malicious_count > 0 else "✅ Clean"
        elif response.status_code == 404:
            result = "Hash not found in VirusTotal."
        else:
            result = f"Error {response.status_code}: {response.json().get('error', {}).get('message', 'Unknown error')}"
    except Exception as e:
        result = f"Error querying VirusTotal: {e}"

    log_to_file(f"{file_hash}: {result}")
    return result

def process_file(file_path, api_key):
    """Process a file: Calculate hash & check VirusTotal, then display results properly."""
    file_hash = calculate_sha256(file_path)
    print(f"\n🔍 Scanning File: {file_path}")
    print(f"🔹 SHA-256: {file_hash}")

    # Check VirusTotal
    result = check_virustotal(api_key, file_hash)

    # Display the final result clearly
    print(f"🛡️ VirusTotal Result: {result}\n")
    
    # Log to file
    log_to_file(f"File: {file_path}\nSHA-256: {file_hash}\nVirusTotal Result: {result}\n")


def scan_directory(directory, api_key):
    """Scan a directory, compute SHA-256, and check VirusTotal with parallel processing."""
    if not os.path.exists(directory):
        print("Invalid directory. Please check the path.")
        return

    print("\nScanning for .exe files in:", directory)
    log_to_file(f"\nScanning started for directory: {directory}\n")

    found_files = False
    exe_files = []

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".exe"):
                found_files = True
                exe_files.append(os.path.join(root, file))

    if not found_files:
        print("No .exe files found in this directory.")
        log_to_file("No .exe files found.\n")
        return

    # Use ThreadPoolExecutor for parallel processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(process_file, file_path, api_key) for file_path in exe_files]
        for future in concurrent.futures.as_completed(futures):
            future.result()  # Ensure all tasks complete

    log_to_file("\nScanning completed.\n")
    print("✅ Scan completed. Results saved in scan_log.txt")

# Get folder path and API key from user
folder_path = input("Enter the folder path to scan: ")
api_key = input("Enter your VirusTotal API key: ")
scan_directory(folder_path, api_key)
