import subprocess

# Define which HTTP methods are safe
SAFE_METHODS = {
    "GET", "POST", "HEAD", "OPTIONS"
}

# Define HTTP methods that typically require a body
METHODS_REQUIRING_BODY = {
    "POST", "PUT", "PATCH", "DELETE"
}

def run_http_method_checks(target_url):
    methods_wordlist_path = "/home/kali/Desktop/Hacksclusive/DigiScan/resources/methods.txt"
    results = []

    # Read HTTP methods from methods.txt file
    with open(methods_wordlist_path, 'r') as file:
        methods = file.read().splitlines()

    for method in methods:
        status_code = check_http_method(target_url, method)
        result = {
            'description': 'Method: {}, Status Code: {}'.format(method, status_code),
            'found': 'Status Code: {}'.format(status_code)
        }

        if method in SAFE_METHODS:
            if status_code == "200":
                result['status'] = 'pass'
                result['advice'] = 'This method is allowed and functioning as expected.'
            else:
                result['status'] = 'warning'
                result['advice'] = 'This method should be allowed but returned an unexpected status code.'
        else:
            if status_code == "200":
                result['status'] = 'fail'
                result['advice'] = 'This method should not be allowed.'
            elif status_code in ["404", "501", "000", "405", "400", "401"]:
                result['status'] = 'pass'
                result['advice'] = 'This method is not allowed as expected.'
            else:
                result['status'] = 'warning'
                result['advice'] = 'This method returned an unexpected status code.'

        results.append(result)

    # Sort results by status importance: fail (cross icon) first, then warning, then pass (checkmark icon)
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results

def check_http_method(target_url, method):
    curl_command = [
        "curl",
        "-s",
        "-L",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "-X",
        method,
        target_url
    ]

    # Add a dummy body for methods requiring a body to avoid 411 errors
    if method in METHODS_REQUIRING_BODY:
        curl_command.extend(["-d", "dummy_body"])

    process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()
    return stdout.strip()
