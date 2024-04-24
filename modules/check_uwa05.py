import json
import subprocess
import os
from urlparse import urlparse  # Ensure compatibility with Python 2.7

def run_testssl(target_url):
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    parsed_url = urlparse(target_url)
    safe_filename = parsed_url.netloc.replace(":", "_").replace("/", "_")
    json_filename = "testssl_output_{}.json".format(safe_filename)
    json_file_path = os.path.join(output_dir, json_filename)

    # Ensure the filename is unique if the file already exists
    file_counter = 1
    while os.path.exists(json_file_path):
        json_file_path = os.path.join(output_dir, "testssl_output_{}_{}.json".format(safe_filename, file_counter))
        file_counter += 1

    try:
        process = subprocess.Popen([testssl_script_path, "-oj", json_file_path, target_url],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print("Error running testssl.sh: {}, {}".format(stderr, stdout))
            return None
    except Exception as e:
        print("Subprocess execution failed: {}".format(str(e)))
        return None

    return json_file_path

def filter_keys(json_file_path):
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
    except IOError as e:
        print("Error reading or parsing JSON file: {}".format(str(e)))
        return []
    except ValueError as e:
        print("JSON data malformed: {}".format(str(e)))
        return []

    return check_compliance(data)

def check_compliance(data):
    results = []
    required_keys = ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
                     "FS_ciphers", "OCSP_stapling", "cert_keySize", "FS_ECDHE_curves",
                     "HSTS_time", "secure_renego", "DH_groups"]
    for item in data:
        if item['id'] in required_keys:
            result = check_key_compliance(item['id'], item['finding'])
            if result:
                results.append(result)
    return results

def check_key_compliance(key, finding):
    # Check compliance for SSL and/or TLS versions
    if key == "TLS1_2":
        if finding == "not offered":
            return {'description': 'TLS 1.2 is not offered', 'status': 'fail', 'advice': 'TLS 1.2 should be enabled'}
        elif finding == "offered":
            return {'description': 'TLS 1.2 is offered', 'status': 'warning', 'advice': 'Consider disabling TLS 1.2 if not strictly needed'}

    if key == "TLS1_3":
        if finding == "not offered":
            return {'description': 'TLS 1.3 is not offered', 'status': 'fail', 'advice': 'TLS 1.3 should be enabled'}
        elif finding == "offered with final":
            return {'description': 'TLS 1.3 is correctly offered with final', 'status': 'pass'}
            
    # Check for OCSP Stapling
    if key == "OCSP_stapling":
        if finding == "not offered":
            return {'description': 'OCSP Stapling is not offered', 'status': 'warning'}
        elif finding == "offered":
            return {'description': 'OCSP Stapling is offered', 'status': 'pass'}
        else:
            return {'description': 'OCSP Stapling status is unclear', 'status': 'fail', 'advice': 'Check OCSP stapling configuration'}

    # Check for Secure Renegotiation
    if key == "secure_renego":
        if finding == "supported":
            return {'description': 'Secure Renegotiation is supported', 'status': 'pass'}
        else:
            return {'description': 'Secure Renegotiation is not supported', 'status': 'fail', 'advice': 'Ensure secure renegotiation is supported'}

    # Check for HSTS Time
    if key == "HSTS_time":
        try:
            hsts_seconds = int(finding.split(" ")[2].strip("()=").split(" ")[0])
            if hsts_seconds >= 31536000:
                return {'description': 'HSTS time meets or exceeds the requirement', 'status': 'pass'}
            else:
                return {'description': 'HSTS time is below the required 31536000 seconds', 'status': 'fail', 'advice': 'Increase HSTS time'}
        except (IndexError, ValueError):
            return {'description': 'HSTS time format is incorrect or missing', 'status': 'fail', 'advice': 'Check HSTS time format'}

    # Check for Certificate Key Size
    if key == "cert_keySize":
        # Convert the finding to Unicode if it's not already and filter digits
        if isinstance(finding, str):
            finding = unicode(finding)  # Ensure finding is treated as a Unicode string
        key_size_str = ''.join([c for c in finding if c.isdigit()])

        if key_size_str:
            try:
                key_size = int(key_size_str)
                if key_size < 2048:
                    return {'description': 'Certificate key size is less than 2048 bits', 'status': 'fail', 'advice': 'Upgrade to at least 2048 bits'}
                elif key_size == 2048:
                    return {'description': 'Certificate key size is exactly 2048 bits', 'status': 'warning', 'advice': 'Consider upgrading to a higher bit size for enhanced security'}
                elif key_size < 3072:
                    return {'description': 'Certificate key size is between 2048 and 3071 bits', 'status': 'warning', 'advice': 'Consider upgrading to a higher bit size for enhanced security'}
                else:
                    return {'description': 'Certificate key size is 3072 bits or more', 'status': 'warning'}
            except ValueError:
                return {'description': 'Unable to parse certificate key size', 'status': 'fail', 'advice': 'Check the certificate key size format'}
        else:
            return {'description': 'No numeric data found in certificate key size', 'status': 'fail', 'advice': 'Verify certificate key size data'}

    # Check for DH Groups
    if key == "DH_groups":
        if "ffdhe4096" in finding or "ffdhe3072" in finding:
            return {'description': 'DH Groups configuration is compliant', 'status': 'pass'}
        else:
            return {'description': 'DH Groups configuration is non-compliant', 'status': 'fail', 'advice': 'Ensure DH Groups include ffdhe4096 or ffdhe3072'}

    # Add checks for other keys as necessary using a similar pattern
    return None
