import json
import subprocess
import os
from urlparse import urlparse  # For Python 2.7 compatibility, use urllib.parse in Python 3.x

def run_testssl(target_url):
    # Using the same logic and setup as in check_uwa05.py
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
    required_keys = {
        "cookie_secure", "cookie_httponly", "HSTS_time", 
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Content-Security-Policy"  # Ensure CSP is included
    }

    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print("Error reading or parsing JSON file: {}".format(str(e)))
        return []

    found_keys = {key: False for key in required_keys}
    results = []

    for item in data:
        key = item['id']
        if key in required_keys:
            found_keys[key] = True  # Mark the key as found
            result = check_header_compliance(key, item['finding'])
            if result:
                results.append(result)

    # Check for any required keys that were not found in the JSON data
    for key, found in found_keys.items():
        if not found:
            results.append({
                'description': '{} is missing'.format(key),
                'status': 'fail',
                'advice': 'Ensure that ' + key + ' is correctly configured and included in the security assessment.'
            })

    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results


def check_header_compliance(key, finding):
    if key == "HSTS_time":
        try:
            hsts_seconds = int(finding.split(" ")[2].strip("()=").split(" ")[0])
            if hsts_seconds >= 31536000:
                return {'description': 'HSTS time meets or exceeds the requirement of 31536000 seconds', 'status': 'pass'}
            else:
                return {'description': 'HSTS time is below the required 31536000 seconds', 'status': 'fail', 'advice': 'Increase HSTS time to at least 31536000 seconds'}
        except (IndexError, ValueError):
            return {'description': 'HSTS time format is incorrect or missing', 'status': 'fail', 'advice': 'Check HSTS time format'}

    if key == "X-Frame-Options":
        valid_options = ["deny", "sameorigin"]
        if finding.lower() in valid_options:
            return {'description': '{} is properly set to {}'.format(key, finding), 'status': 'pass'}
        else:
            return {'description': '{} setting is not optimal'.format(key), 'status': 'fail', 'advice': 'Set {} to either "DENY" or "SAMEORIGIN"'.format(key)}

    if key == "X-Content-Type-Options":
        if finding.lower() == "nosniff":
            return {'description': '{} is set to nosniff'.format(key), 'status': 'pass'}
        else:
            return {'description': '{} is not set to nosniff'.format(key), 'status': 'fail', 'advice': 'Set {} to "nosniff"'.format(key)}

    if key == "Referrer-Policy":
        valid_policies = ["same-origin", "noreferrer"]
        if finding.lower() in valid_policies:
            return {'description': '{} is adequately set to {}'.format(key, finding), 'status': 'pass'}
        else:
            return {'description': '{} setting is not optimal'.format(key), 'status': 'fail', 'advice': 'Set {} to either "same-origin" or "noreferrer"'.format(key)}


    if key == "Content-Security-Policy":
        csp_errors = []
        if "'unsafe-inline'" in finding and "nonce" not in finding:
            csp_errors.append("Contains 'unsafe-inline' without 'nonce'")
        if "'unsafe-eval'" in finding:
            csp_errors.append("Contains 'unsafe-eval'")
        if "http:" in finding:
            csp_errors.append("Contains HTTP sources which are insecure")

        required_directives = ["default-src 'self'", "frame-src 'self'", "frame-ancestors 'self'"]
        for directive in required_directives:
            if directive not in finding:
                csp_errors.append("Missing directive: {}".format(directive))

        if csp_errors:
            return {'description': '{} has issues: {}'.format(key, ', '.join(csp_errors)), 'status': 'fail', 'advice': 'Adjust CSP to conform to DigiD standards: {}'.format(', '.join(csp_errors))}
        else:
            return {'description': '{} is correctly configured according to DigiD standards'.format(key), 'status': 'pass'}


    return None
