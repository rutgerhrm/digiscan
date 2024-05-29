import subprocess
import time

# Define which HTTP methods are considered safe
SAFE_METHODS = {
    "GET", "POST"
}

def run_http_method_checks(target_url):
    """
    Run HTTP method checks on the target URL.

    Reads the HTTP methods from a wordlist and checks each method on the target URL.
    Returns the results with a status indicating if the method is safe, a warning, or should be restricted.
    """
    methods_wordlist_path = "/home/kali/Desktop/Hacksclusive/DigiScan/resources/methods.txt"
    results = []

    # Read HTTP methods from methods.txt file
    with open(methods_wordlist_path, 'r') as file:
        methods = file.read().splitlines()

    # Check each method on the target URL
    for method in methods:
        status_code = check_http_method(target_url, method)
        result = {
            'description': 'Method: {}, Status Code: {}'.format(method, status_code),
            'found': 'Status Code: {}'.format(status_code)
        }

        # Determine the status and advice based on the method and status code
        if method in SAFE_METHODS:
            if status_code == "200":
                result['status'] = 'pass'
                result['advice'] = 'The method is allowed and functioning as expected.'
            else:
                result['status'] = 'warning'
                result['advice'] = 'Method should be allowed but is not responding as expected.'
        else:
            if status_code == "200":
                result['status'] = 'fail'
                result['advice'] = 'This method should not be allowed. Investigate and restrict access.'
            elif status_code in ["404", "501", "000", "405", "400", "401"]:
                result['status'] = 'pass'
                result['advice'] = 'Method is either not found or not implemented as expected.'
            else:
                result['status'] = 'warning'
                result['advice'] = 'Unexpected status code for method. Needs further investigation.'

        results.append(result)

    # Sort results by status importance: fail (cross icon) first, then warning, then pass (checkmark icon)
    results.sort(key=lambda x: {"fail": 0, "warning": 1, "pass": 2}[x['status']])
    return results

def check_http_method(target_url, method):
    """
    Check the response status code for a given HTTP method on the target URL.

    Uses curl to send the HTTP request and returns the status code.
    """
    max_retries = 5  # Maximum number of retries for status code 429
    retry_delay = 2  # Initial delay in seconds before retrying

    for attempt in range(max_retries):
        # Construct the curl command
        curl_command = [
            "curl",
            "-s",  # Silent mode
            "-L",  # Follow redirects
            "-o",  # Output to /dev/null
            "/dev/null",
            "-w",  # Write out HTTP status code
            "%{http_code}",
            "-X",  # Specify HTTP request method
            method,
            target_url
        ]

        # Add Content-Length header for methods that typically require a body
        if method in ["POST", "PUT"]:
            curl_command.extend(["-H", "Content-Length: 0"])

        # Execute the curl command
        process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        status_code = stdout.strip()

        # Handle status code 429 (Too Many Requests)
        if status_code == "429":
            if attempt < max_retries - 1:
                print("Received status code 429. Retrying in {} seconds...".format(retry_delay))
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
            else:
                print("Max retries reached. Aborting...")
                break

        # Handle status code 411 (Length Required)
        elif status_code == "411":
            print("Received status code 411. Adding Content-Length header.")
            if method in ["POST", "PUT"]:
                curl_command.extend(["-H", "Content-Length: 0"])
            else:
                break

        # Return the status code for all other cases
        else:
            return status_code

    # Return the last status code if retries are exhausted or for 411 without retry
    return status_code
