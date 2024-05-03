# IS NOG NIET COMPLIANT AAN DIGID EISEN, WORDT VERANDERT
import subprocess

def run_http_method_checks(target_url):
    methods_wordlist_path = "/home/kali/Desktop/Hacksclusive/DigiScan/resources/methods.txt"
    results = []

    with open(methods_wordlist_path, 'r') as file:
        methods = file.read().splitlines()

    for method in methods:
        status_code = check_http_method(target_url, method)
        if status_code == "200":
            results.append({
                'description': 'Method: {}, Status Code: {}'.format(method, status_code),
                'status': 'pass',
                'advice': 'The method is allowed and functioning as expected.',
                'found': 'Status Code: {}'.format(status_code)
            })
        elif status_code in ["404", "501"]:
            results.append({
                'description': 'Method: {}, Status Code: {}'.format(method, status_code),
                'status': 'warning',
                'advice': 'Method is either not found or not implemented but is non-critical.',
                'found': 'Status Code: {}'.format(status_code)
            })
        else:
            results.append({
                'description': 'Method: {}, Status Code: {}'.format(method, status_code),
                'status': 'fail',
                'advice': 'Method should not be allowed or needs investigation.',
                'found': 'Status Code: {}'.format(status_code)
            })

    return results

def check_http_method(target_url, method):
    curl_command = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        method,
        target_url
    ]
    process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    return stdout.strip()
