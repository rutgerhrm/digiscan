import json
import subprocess
import os
from urlparse import urlparse

def run_testssl(target_url, lock, json_file_path):
    # Runs the testssl.sh script on the target URL and ensures the output file is unique (CHANGE FILE PATH)
    testssl_script_path = "/home/kali/digiscan/tools/testssl.sh/testssl.sh"
    output_dir = os.path.dirname(json_file_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    lock.acquire()
    try:
        # Ensure the filename is unique if the file already exists
        file_counter = 1
        while os.path.exists(json_file_path):
            json_file_path = os.path.join(output_dir, "testssl_output_{}_{}.json".format(
                urlparse(target_url).netloc.replace(":", "_").replace("/", "_"), file_counter))
            file_counter += 1

        process = subprocess.Popen([testssl_script_path, "-oj", json_file_path, target_url],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print("Error running testssl.sh: {}, {}".format(stderr, stdout))
            return None
    except Exception as e:
        print("Subprocess execution failed: {}".format(str(e)))
        return None
    finally:
        lock.release()  # Ensure that the lock is always released

    return json_file_path

def filter_keys(json_file_path):
    # Filters the relevant keys from the JSON data output by testssl.sh
    required_keys = {
        "cookie_secure", "cookie_httponly", "HSTS_time", 
        "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
        "Content-Security-Policy" 
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
            status = 'warning' if key in ["cookie_secure", "cookie_httponly"] else 'fail'
            results.append({
                'description': '{} is missing'.format(key),
                'status': status,
                'advice': 'Ensure that ' + key + ' is correctly configured and included in the security assessment.'
            })

    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results

def run_ffuf_scan(target_url):
    # Runs the ffuf tool to scan for hidden files and directories on the target URL
    ffuf_path = "/usr/local/bin/ffuf" 
    wordlist_path = "/home/kali/Desktop/Hacksclusive/DigiScan/resources/wordlist.txt"
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    parsed_url = urlparse(target_url)
    safe_filename = parsed_url.netloc.replace(":", "_").replace("/", "_")
    json_filename = "ffuf_output_{}.json".format(safe_filename)
    json_file_path = os.path.join(output_dir, json_filename)

    # Check for existing file and increment filename if exists
    file_counter = 1
    while os.path.exists(json_file_path):
        json_file_path = os.path.join(output_dir, "ffuf_output_{}_{}.json".format(safe_filename, file_counter))
        file_counter += 1

    ffuf_command = [
        ffuf_path,
        "-w", wordlist_path,
        "-u", target_url + "/FUZZ",
        "-mc", "200", 
        "-o", json_file_path,
        "-r"
    ]

    try:
        process = subprocess.Popen(ffuf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print("FFUF command failed with return code:", process.returncode)
            return None

        if os.path.exists(json_file_path):
            print("FFUF output file created at:", json_file_path)
            return json_file_path
        else:
            print("Expected FFUF output file was not created:", json_file_path)
            return None
    except Exception as e:
        print("Failed to execute FFUF command:", str(e))
        return None

def parse_ffuf_output(json_file_path):
    # Parses the output JSON file from ffuf and extracts relevant information
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
    except Exception as e:
        print("Error reading or parsing ffuf JSON file: {}".format(str(e)))
        return []

    results = []
    for result in data.get('results', []):
        results.append({
            'description': 'Found: {} at {}'.format(result['input']['FUZZ'], result['url']),
            'status': 'warning', 
            'advice': 'Check the exposure of this directory/file.'
        })
    return results

def check_header_compliance(key, finding):
    # Checks the compliance of HTTP headers based on predefined rules
    csp_errors = []

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
        required_directives = {
            "default-src": "'self'",
            "frame-src": "'self'",
            "frame-ancestors": "'self'"
        }

        csp_policies = {}
        for directive in finding.split(";"):
            if directive.strip():
                parts = directive.strip().split(" ")
                directive_name = parts[0].strip()
                sources = " ".join(parts[1:]).strip()
                csp_policies[directive_name] = sources

        # Check each required directive
        for directive, expected_value in required_directives.items():
            actual_value = csp_policies.get(directive, 'none')
            if actual_value != expected_value:
                csp_errors.append("Expected {directive} {expected}, found {actual}".format(directive=directive, expected=expected_value, actual=actual_value))

        advice_list = []

        # Additional checks for unsafe practices
        if "'unsafe-inline'" in finding and "nonce" not in finding:
            csp_errors.append("Contains 'unsafe-inline' without 'nonce'")
            advice_list.append("no 'unsafe-inline' unless 'nonce' present")
        if "'unsafe-eval'" in finding:
            csp_errors.append("Contains 'unsafe-eval'")
            advice_list.append("no 'unsafe-eval'")
        if "http:" in finding:
            csp_errors.append("Contains HTTP sources which are insecure")
            advice_list.append("no http-sources (https only)")

        # Check and add advice for required directives
        for directive, expected_value in required_directives.items():
            actual_value = csp_policies.get(directive)
            if actual_value != expected_value:
                advice_list.append("Set {} to {}".format(directive, expected_value))

        if csp_errors:
            return {
                'description': "{} has issues: {}".format(key, ', '.join(csp_errors)),
                'status': 'fail',
                'advice': 'Adjust CSP to conform to DigiD standards: ' + ', '.join(advice_list),
            }
        else:
            return {'description': "{} is correctly configured according to DigiD standards".format(key), 'status': 'pass'}

    return {'description': 'No specific checks implemented for this header', 'status': 'info'}
