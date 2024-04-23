import os
import subprocess
import json
import tempfile
import time
import sys
from utilities.animation import start_loading_animation, stop_loading_animation
from utilities.filtering import filter_testssl_output, filter_ffuf_output
from utilities.banner import BANNER

# ANSI color codes for formatting
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
ORANGE = "\033[93m"

def run_testssl_with_url(url):
    # Full path to testssl.sh script
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"

    # Create a temporary directory to store the JSON output file
    temp_dir = tempfile.mkdtemp()

    # Run the testssl.sh script with the provided URL and generate JSON output file
    json_file_path = os.path.join(temp_dir, "output.json")

    start_loading_animation("testssl")

    with open(os.devnull, 'w') as devnull:
        subprocess.run(
            [testssl_script_path, "-oj", json_file_path, url],
            stdout=devnull,  # Suppress standard output
            stderr=subprocess.PIPE  # Capture standard error (if needed)
        )

    stop_loading_animation()
    print()

    # Read the JSON output from the file
    with open(json_file_path, 'r') as file:
        json_data = file.read()

    # Clean up temporary directory
    os.remove(json_file_path)
    os.rmdir(temp_dir)

    return json_data

def colorize_tls_version(version_value):
    if "not offered" in version_value:
        return GREEN + version_value + RESET
    elif "offered with final" in version_value:
        return GREEN + version_value + RESET
    elif "offered" in version_value:
        return ORANGE + version_value + RESET
    else:
        return RED + version_value + RESET

#!!!not offered blijft steeds groen ipv oranje
def colorize_ocsp_stapling(ocsp_value):
    if ocsp_value == "not offered":
        return ORANGE + ocsp_value + RESET
    elif ocsp_value == "offered":
        return GREEN + ocsp_value + RESET
    else:
        return RED + ocsp_value + RESET

def colorize_cert_key_size(key_size):
    try:
        key_size_int = int(key_size.split(' ')[1])
        if key_size_int < 2048:
            return RED + key_size + RESET
        elif 2048 <= key_size_int <= 3071:
            return ORANGE + key_size + RESET
        else:
            return GREEN + key_size + RESET
    except:
        return RED + key_size + RESET

# def colorize_hsts_time(hsts_value):
#     try:
#         seconds = int(hsts_value.split('=')[1].split(' ')[0])
#         if seconds >= 31536000:
#             return GREEN + hsts_value + RESET
#         else:
#             return RED + hsts_value + RESET
#     except:
#         return RED + hsts_value + RESET

# Print the banner
print(BANNER)

url = input("> Enter the URL to test: ")

json_data = run_testssl_with_url(url)

# Filter testssl output
data = json.loads(json_data)
filtered_ssl_tls, filtered_headers = filter_testssl_output(data)

# Print the filtered results
if filtered_ssl_tls is not None and filtered_headers is not None:
    print("\n\033[1mTestSSL Results:\033[0m\n")
    print(BOLD + "U/WA.05:" + RESET)
    for key, value in filtered_ssl_tls.items():
        if "TLS" in key:
            value = colorize_tls_version(value)
        # elif "time" in key:
        #     value = colorize_hsts_time(value)
        elif key == "cert_keySize":
            value = colorize_cert_key_size(value)
        elif key == "OCSP_stapling":
            value = colorize_ocsp_stapling(value)
        else:
            if value != "not found":
                value = GREEN + value + RESET
            else:
                value = RED + value + RESET
        print(f"  {BOLD}{key}:{RESET} {value}")

    print("\n" + BOLD + "U/PW.03 Header Results:" + RESET)
    for key, value in filtered_headers.items():
        if value != "not found":
            value = GREEN + value + RESET
        else:
            value = RED + value + RESET
        print(f"  {BOLD}{key}:{RESET} {value}")

def run_ffuf(url):
    # Create a temporary directory to store the JSON output file
    temp_dir = tempfile.mkdtemp()

    # Path to temporary JSON output file
    json_file_path = os.path.join(temp_dir, "ffuf_output.json")

    start_loading_animation("ffuf")

    # Execute the ffuf command and write output to the temporary JSON file
    with open(os.devnull, 'w') as devnull:
        subprocess.run(
            ["ffuf", "-w", "/home/kali/Desktop/wl.txt", "-u", f"{url}/FUZZ", "-e", ".asp,.csv,.php,.html,.txt", "-o", json_file_path],
            stdout=devnull,  # Suppress standard output
            stderr=subprocess.PIPE  # Capture standard error (if needed)
        )
    stop_loading_animation()
    print()

    # Read the JSON output from the file
    with open(json_file_path, 'r') as file:
        json_data = json.load(file)

    # Filter the ffuf results
    filtered_ffuf_results = filter_ffuf_output(json_data)

    # Clean up temporary directory
    os.remove(json_file_path)
    os.rmdir(temp_dir)

    return filtered_ffuf_results

# Run ffuf and get the JSON output
ffuf_results = run_ffuf(url)

# Print the filtered ffuf results
print("\n\033[1mU/PW.03 Directory Listing Results:\033[0m\n")  # Bold title
for result in ffuf_results:
    print(f"\033[1mFUZZ:\033[0m {result['FUZZ']}, \033[1mStatus:\033[0m {result['status']}, \033[1mURL:\033[0m {result['url']}")
