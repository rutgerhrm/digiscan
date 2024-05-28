import json
import subprocess
import os
import re
from urlparse import urlparse

# Load the configuration settings from a JSON file
def load_config():
    config_path = '/home/kali/Desktop/Hacksclusive/DigiScan/resources/config.json'
    with open(config_path, 'r') as file:
        return json.load(file)

# Global variable to hold the configuration data
config = load_config()

# Function to run testssl.sh on a given URL
def run_testssl(target_url, lock, json_file_path):
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"
    output_dir = os.path.dirname(json_file_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Acquire a lock to ensure exclusive access
    lock.acquire()
    try:
        # Ensure the filename is unique if the file already exists
        file_counter = 1
        while os.path.exists(json_file_path):
            json_file_path = os.path.join(output_dir, "testssl_output_{}_{}.json".format(
                urlparse(target_url).netloc.replace(":", "_").replace("/", "_"), file_counter))
            file_counter += 1

        # Run the testssl.sh script
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

# Function to filter and check the relevant keys from the JSON data output by testssl.sh
def filter_keys(json_file_path):
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
                'description': '{} is missing'.format(config[key]["friendly_name"]),
                'status': status,
                'advice': 'Ensure that ' + config[key]["friendly_name"] + ' is correctly configured and included in the security assessment.'
            })

    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results

# Function to run FFUF scan on a given URL
def run_ffuf_scan(target_url):
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

# Function to parse the output from FFUF scan
def parse_ffuf_output(json_file_path):
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

# Function to check the compliance of header configurations
def check_header_compliance(key, finding):
    # Special handling for HSTS_time key
    if key == "HSTS_time":
        try:
            # Extract the HSTS seconds from the finding string
            match = re.search(r'(\d+)\s*seconds', finding)
            if match:
                hsts_seconds = int(match.group(1))
                for rule in config[key]["rules"]:
                    if evaluate_range(rule['range'], hsts_seconds):
                        return create_response(config[key]["friendly_name"], finding, rule)
            else:
                return {
                    'description': 'HSTS time format is incorrect or missing',
                    'status': 'fail',
                    'advice': 'Check HSTS time format'
                }
        except (IndexError, ValueError):
            return {
                'description': 'HSTS time format is incorrect or missing',
                'status': 'fail',
                'advice': 'Check HSTS time format'
            }

    # General handling for other keys based on the JSON configuration
    if key in config and 'friendly_name' in config[key]:
        friendly_name = config[key]['friendly_name']
        if finding.lower() in config[key]:
            return create_response(friendly_name, finding, config[key][finding.lower()])
        elif 'default' in config[key]:
            return create_response(friendly_name, finding, config[key]['default'])

    # Handling for Content-Security-Policy
    if key == "Content-Security-Policy":
        required_directives = config[key]['required_directives']
        csp_policies = {}
        for directive in finding.split(";"):
            if directive.strip():
                parts = directive.strip().split(" ")
                directive_name = parts[0].strip()
                sources = " ".join(parts[1:]).strip()
                csp_policies[directive_name] = sources

        csp_errors = []
        advice_list = []

        # Check each required directive
        for directive, expected_value in required_directives.items():
            actual_value = csp_policies.get(directive, 'none')
            if actual_value != expected_value:
                csp_errors.append("Expected {} {}, found {}".format(directive, expected_value, actual_value))

        # Additional checks for unsafe practices
        if "'unsafe-inline'" in finding and "nonce" not in finding:
            csp_errors.append("Contains 'unsafe-inline' without 'nonce'")
            advice_list.append(config[key]['advice_list'][0])
        if "'unsafe-eval'" in finding:
            csp_errors.append("Contains 'unsafe-eval'")
            advice_list.append(config[key]['advice_list'][1])
        if "http:" in finding:
            csp_errors.append("Contains HTTP sources which are insecure")
            advice_list.append(config[key]['advice_list'][2])

        # Add advice for each required directive
        for directive, expected_value in required_directives.items():
            actual_value = csp_policies.get(directive)
            if actual_value != expected_value:
                advice_list.append("Set {} to {}".format(directive, expected_value))

        if csp_errors:
            return {
                'description': "{} has issues: {}".format(config[key]["friendly_name"], ', '.join(csp_errors)),
                'status': 'fail',
                'advice': 'Adjust CSP to conform to DigiD standards: ' + ', '.join(advice_list),
            }
        else:
            return {
                'description': "{} is correctly configured according to DigiD standards".format(config[key]["friendly_name"]),
                'status': 'pass'
            }

    return {
        'description': 'No specific checks implemented for this header',
        'status': 'info'
    }

# Function to evaluate if a value falls within a specified range
def evaluate_range(range_str, value):
    try:
        if isinstance(value, str):
            match = re.match(r'(\d+)', value)
            num_value = int(match.group(1)) if match else None
        else:
            num_value = value

        if num_value is not None:
            if range_str.startswith('>='):
                return num_value >= int(range_str[2:])
            elif range_str.startswith('<='):
                return num_value <= int(range_str[2:])
            elif range_str.startswith('<'):
                return num_value < int(range_str[1:])
            elif range_str.startswith('>'):
                return num_value > int(range_str[1:])
            elif '-' in range_str:
                min_val, max_val = map(int, range_str.split('-'))
                return min_val <= num_value <= max_val
    except ValueError as e:
        print("Exception in evaluate_range:", e)
    return False

# Function to create a response dictionary based on the compliance result
def create_response(friendly_name, finding, rule):
    return {
        'description': "{} is {}".format(friendly_name, finding),
        'status': rule['status'],
        'advice': rule['advice']
    }
