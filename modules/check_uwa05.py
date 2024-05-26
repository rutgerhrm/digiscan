import json
import subprocess
import os
import re
from urlparse import urlparse 

def run_testssl(target_url, lock, json_file_path):
    testssl_script_path = "/home/kali/Desktop/Hacksclusive/testssl.sh/testssl.sh"
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
    required_keys = {
        "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
        "FS_ciphers", "OCSP_stapling", "cert_keySize", "FS_ECDHE_curves",
        "secure_renego", "DH_groups"
    }
    
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
                'description': '{} is missing'.format(key),
                'status': 'fail',
                'advice': 'Ensure that ' + key + ' is correctly configured and included in the security assessment.'
            })
    
    # Sort results by status importance
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    
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

    # Check for Certificate Key Size
    if key == "cert_keySize":
        # This regex matches any sequence of digits that are followed by ' bits'
        key_size_match = re.search(r'(\d+)\s*bits', finding)
        if key_size_match:
            key_size_str = key_size_match.group(1)  # Extracts the first group of digits before ' bits'
            try:
                key_size = int(key_size_str)
                if key_size < 2048:
                    return {'description': 'Certificate key size is less than 2048 bits', 'status': 'fail', 'advice': 'Upgrade to at least 2048 bits'}
                elif key_size == 2048:
                    return {'description': 'Certificate key size is exactly 2048 bits', 'status': 'warning', 'advice': 'Consider upgrading to a higher bit size for enhanced security'}
                elif key_size < 3072:
                    return {'description': 'Certificate key size is between 2048 and 3071 bits', 'status': 'warning', 'advice': 'Consider upgrading to 3072 bits or more for enhanced security'}
                else:
                    return {'description': 'Certificate key size is 3072 bits or more', 'status': 'pass'}
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

    if key == "FS_ciphers":
        # Define cipher suites categories
        pass_ciphers = {
            'key_exchange': ['ECDHE'],
            'certificate': ['ECDSA'],
            'encryption': ['AES_256_GCM', 'CHACHA20_POLY1305', 'AES_128_GCM'],
            'hash': ['SHA384', 'SHA256']
        }
        warning_ciphers = {
            'encryption': ['AES_256_CBC', 'AES_128_CBC'],
            'hash': ['SHA1']
        }
        fail_ciphers = {
            'key_exchange': ['TLS_RSA_WITH'],
            'encryption': ['3DES_EDE_CBC', 'DES_CBC3']
        }

        # Analyzing the finding for cipher status
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

        return {'description': "FS Ciphers evaluation: {}".format(description), 'status': overall_status, 'advice': "Review cipher suite configuration according to the latest security standards."}

    if key == "FS_ECDHE_curves":
        # Define acceptable curve standards
        pass_curves = ["secp384r1", "secp256r1", "X448", "X25519"]
        warning_curves = ["secp224r1"]
        curves = finding.split()
        
        # Analyze the curve findings
        result_details = []
        for curve in curves:
            if curve in pass_curves:
                result_details.append((curve, 'pass'))
            elif curve in warning_curves:
                result_details.append((curve, 'warning'))
            else:
                result_details.append((curve, 'fail'))
        
        # Determine overall status based on presence of any fail or warning curves
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

    return None
