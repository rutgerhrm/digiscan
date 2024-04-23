import json
import subprocess
import os

def run_testssl(target_url):
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    json_file_path = os.path.join(output_dir, "testssl_output.json")

    process = subprocess.Popen(
        [testssl_script_path, "-oj", json_file_path, target_url],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print("testssl.sh failed to execute:")
        print("STDOUT:", stdout)
        print("STDERR:", stderr)
    else:
        print("testssl.sh executed successfully, results saved to", json_file_path)

    if os.path.exists(json_file_path) and os.path.getsize(json_file_path) > 0:
        return json_file_path
    else:
        print("No output file created or file is empty")
        return None

def filter_keys(json_file_path):
    keys_of_interest = [
        "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
        "FS_ciphers", "OCSP_stapling", "cert_keySize", "FS_ECDHE_curves",
        "HSTS_time", "secure_renego", "DH_groups"
    ]

    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)

        filtered_data = {item["id"]: item["finding"] for item in data if item["id"] in keys_of_interest}
        print("Filtered data:", filtered_data)
        return filtered_data

    except Exception as e:
        print("Error reading or parsing JSON file:", str(e))
        return {}
