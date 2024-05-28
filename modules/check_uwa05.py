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

# Define required keys based on the JSON configuration
required_keys = set(config.keys())

# Function to get friendly name from the configuration
def get_friendly_name(key):
    return config.get(key, {}).get("friendly_name", key)

# Function to run testssl.sh on a given URL, manage file output, and handle subprocesses
def run_testssl(target_url, lock, json_file_path):
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"
    output_dir = os.path.dirname(json_file_path)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    lock.acquire()
    try:
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
        lock.release()

    return json_file_path

# Filter and extract relevant keys from the JSON data output by testssl.sh
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

# Check the compliance of the data against configured norms
def check_compliance(data):
    results = []
    # Create a dictionary to check which keys were found
    found_keys = {key: False for key in required_keys}

    # Check each item in the JSON data
    for item in data:
        key = item['id']
        if key in required_keys:
            found_keys[key] = True
            result = check_key_compliance(key, item['finding'])
            if result:
                results.append(result)

    # Check for any required keys that were not found in the JSON data
    for key, found in found_keys.items():
        if not found:
            results.append({
                'description': '{} is missing'.format(get_friendly_name(key)),
                'status': 'fail',
                'advice': 'Ensure that ' + get_friendly_name(key) + ' is correctly configured and included in the security assessment.'
            })

    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    
    return results

# Determine compliance of a specific finding based on configuration rules
def check_key_compliance(key, finding):
    if key == "FS_ciphers":
        return check_fs_ciphers_compliance(finding)
    if key == "FS_ECDHE_curves":
        return check_fs_ecdhe_curves_compliance(finding)
    if key == "cert_keySize":
        return check_cert_key_size_compliance(finding)
    if key in config:
        rules = config[key].get('rules', [])
        for rule in rules:
            if 'exact' in rule and rule['exact'] == finding:
                return create_response(key, finding, rule)
            elif 'range' in rule:
                if evaluate_range(rule['range'], finding):
                    return create_response(key, finding, rule)
        if finding in config[key]:
            return create_response(key, finding, config[key][finding])
        if 'default' in config[key]:
            return create_response(key, finding, config[key]['default'])

    return {
        'description': "{} compliance with {} is not clear".format(get_friendly_name(key), finding),
        'status': 'fail',
        'advice': "Check the configuration for {}".format(get_friendly_name(key))
    }

# Evaluate if a numeric value matches a specified range
def evaluate_range(range_str, value):
    match = re.match(r'(\d+)', value)
    if match:
        num_value = int(match.group(1))
        if '<' in range_str and num_value < int(range_str[1:]):
            return True
        elif '>' in range_str and num_value > int(range_str[1:]):
            return True
        elif '-' in range_str:
            min_val, max_val = map(int, range_str.split('-'))
            return min_val <= num_value <= max_val
        elif '>=' in range_str and num_value >= int(range_str[2:]):
            return True
    return False

# Check FS ciphers compliance
def check_fs_ciphers_compliance(finding):
    pass_ciphers = config['FS_ciphers']['categories']['pass']
    warning_ciphers = config['FS_ciphers']['categories']['warning']
    fail_ciphers = config['FS_ciphers']['categories']['fail']

    ciphers = finding.split()
    statuses = []

    for cipher in ciphers:
        status = 'pass'  # Default status
        for category, values in fail_ciphers.items():
            if any(value in cipher for value in values):
                status = 'fail'
                break
        if status != 'fail':
            for category, values in warning_ciphers.items():
                if any(value in cipher for value in values):
                    status = 'warning'
                    break
        if status != 'fail' and status != 'warning':
            if not any(any(value in cipher for value in pass_ciphers[cat]) for cat in pass_ciphers):
                status = 'fail'  # If none of the pass conditions are met, default to fail

        statuses.append((cipher, status))

    description = ', '.join(["{} ({})".format(cipher, stat) for cipher, stat in statuses])
    overall_status = 'pass' if all(stat == 'pass' for _, stat in statuses) else 'warning' if any(stat == 'warning' for _, stat in statuses) else 'fail'

    return {
        'description': "FS Ciphers evaluation: {}".format(description),
        'status': overall_status,
        'advice': "Review cipher suite configuration according to the latest security standards."
    }

# Check FS ECDHE curves compliance
def check_fs_ecdhe_curves_compliance(finding):
    pass_curves = config['FS_ECDHE_curves']['pass']
    warning_curves = config['FS_ECDHE_curves']['warning']
    curves = finding.split()

    result_details = []
    for curve in curves:
        if curve in pass_curves:
            result_details.append((curve, 'pass'))
        elif curve in warning_curves:
            result_details.append((curve, 'warning'))
        else:
            result_details.append((curve, 'fail'))

    if any(curve_status == 'fail' for _, curve_status in result_details):
        overall_status = 'fail'
    elif any(curve_status == 'warning' for _, curve_status in result_details):
        overall_status = 'warning'
    else:
        overall_status = 'pass'

    description = ', '.join(["{} ({})".format(curve, status) for curve, status in result_details])
    return {
        'description': "ECDHE Curves evaluation: {}".format(description),
        'status': overall_status,
        'advice': "Review ECDHE curve configurations to ensure they align with current security standards."
    }

# Check certificate key size compliance
def check_cert_key_size_compliance(finding):
    key_size_match = re.search(r'(\d+)\s*bits', finding)
    if key_size_match:
        key_size_str = key_size_match.group(1)  # Extracts the first group of digits before ' bits'
        try:
            key_size = int(key_size_str)
            for rule in config["cert_keySize"]["rules"]:
                if 'range' in rule and evaluate_range(rule['range'], key_size_str):
                    return create_response("Certificate key size", finding, rule)
                elif 'exact' in rule and rule['exact'] == key_size_str:
                    return create_response("Certificate key size", finding, rule)
            # Fallback case if no rules match
            return {
                'description': 'Certificate key size is {} bits'.format(key_size_str),
                'status': 'fail',
                'advice': 'Check the certificate key size format'
            }
        except ValueError:
            return {
                'description': 'Unable to parse certificate key size',
                'status': 'fail',
                'advice': 'Check the certificate key size format'
            }
    else:
        return {
            'description': 'No numeric data found in certificate key size',
            'status': 'fail',
            'advice': 'Verify certificate key size data'
        }

# Create a response dictionary based on the compliance result
def create_response(key, finding, rule):
    return {
        'description': "{} is {}".format(get_friendly_name(key), finding),
        'status': rule['status'],
        'advice': rule['advice'] if 'advice' in rule else 'No specific advice available.'
    }
