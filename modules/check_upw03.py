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
    required_keys = {"cookie_secure", "cookie_httponly", "HSTS_time", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"}
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print("Error reading or parsing JSON file: {}".format(str(e)))
        return []

    results = []
    for item in data:
        key = item['id']
        if key in required_keys:
            result = check_header_compliance(key, item['finding'])
            if result:
                results.append(result)

    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results

def check_header_compliance(key, finding):
    if key == "HSTS_time":
        try:
            hsts_seconds = int(finding.split(" ")[2].strip("()=").split(" ")[0])
            if hsts_seconds >= 31536000:
                return {'description': '{} time meets or exceeds the requirement'.format(key), 'status': 'pass'}
            else:
                return {'description': '{} time is below the required 31536000 seconds'.format(key), 'status': 'fail', 'advice': 'Increase {} time'.format(key)}
        except (IndexError, ValueError):
            return {'description': '{} time format is incorrect or missing'.format(key), 'status': 'fail', 'advice': 'Check {} time format'.format(key)}
    if key in ["cookie_secure", "cookie_httponly"]:
        if finding.lower() == "set":
            return {'description': '{} is properly set'.format(key), 'status': 'pass'}
        else:
            return {'description': '{} is not set'.format(key), 'status': 'fail', 'advice': 'Set {} to enhance security'.format(key)}
    if key == "X-Frame-Options":
        if finding.lower() in ["sameorigin", "deny"]:
            return {'description': '{} is properly set to {}'.format(key, finding), 'status': 'pass'}
        else:
            return {'description': '{} setting is not optimal'.format(key), 'status': 'warning', 'advice': 'Set {} to either "SAMEORIGIN" or "DENY"'.format(key)}
    if key == "X-Content-Type-Options":
        if finding.lower() == "nosniff":
            return {'description': '{} is set to nosniff'.format(key), 'status': 'pass'}
        else:
            return {'description': '{} is not set to nosniff'.format(key), 'status': 'fail', 'advice': 'Set {} to "nosniff"'.format(key)}
    if key == "Referrer-Policy":
        recommended_policies = ["no-referrer", "strict-origin-when-cross-origin"]
        if finding.lower() in recommended_policies:
            return {'description': '{} is adequately set to {}'.format(key, finding), 'status': 'pass'}
        else:
            return {'description': '{} setting is not optimal'.format(key), 'status': 'warning', 'advice': 'Set {} to a more restrictive setting like "no-referrer" or "strict-origin-when-cross-origin"'.format(key)}

    return None

