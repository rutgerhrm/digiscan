import subprocess
import json

def run_server_check(target_url):
    """
    Run server check which includes fetching the server header and running Wappalyzer.
    Combines results from both checks into a single list.
    """
    server_results = fetch_server_header(target_url)
    technology_results = run_wappalyzer(target_url)
    return server_results + technology_results

def fetch_server_header(target_url):
    """
    Fetch the server header using curl command.
    Extracts and returns the server header information.
    """
    curl_command = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{header[server]}"
    ]
    curl_command.append(target_url)

    process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()

    return format_server_header_results(stdout.strip())

def format_server_header_results(server_header):
    """
    Formats the server header results into a dictionary with description, status, advice, and found fields.
    """
    if server_header:
        return [{
            'description': 'Server Header Information',
            'status': 'warning',
            'advice': 'Server header is visible, which could reveal sensitive information about the server configuration.',
            'found': 'Server: {}'.format(server_header)
        }]
    else:
        return [{
            'description': 'Server Header Information',
            'status': 'pass',
            'advice': 'No server header present or the HTTP banner does not reveal server information.'
        }]

def run_wappalyzer(target_url):
    """
    Runs Wappalyzer to detect technologies used by the target URL.
    Parses the output and returns formatted results.
    """
    wappalyzer_cmd = [
        "wappalyzer",
        "--disable-ssl",
        "--json",
        "--target",
        target_url
    ]
    process = subprocess.Popen(wappalyzer_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()

    try:
        data = json.loads(stdout)
        return format_wappalyzer_results(data)
    except json.JSONDecodeError:
        return [{
            'description': 'Wappalyzer Technology Check',
            'status': 'fail',
            'advice': 'Failed to parse Wappalyzer output or command failed.',
            'found': 'Invalid JSON output'
        }]

def format_wappalyzer_results(data):
    """
    Formats the Wappalyzer results into a list of dictionaries with description, status, advice, and found fields.
    """
    results = []
    for tech, details in data.items():
        # Check if the version is already included in the technology name
        if ':' in tech and details.get('version') is None:
            version_info = tech  # Use the tech string as it includes the version
        elif details.get('version'):
            version_info = "{}: {}".format(tech, details.get('version'))
        else:
            version_info = "{}: N/A".format(tech)  # Append N/A only if no version is available

        results.append({
            'description': "Technology Detected: {}".format(tech.split(':')[0]),  # Display only the technology name
            'status': 'warning',
            'advice': 'Identified technology and its version may disclose sensitive configuration details.',
            'found': version_info
        })
    return results
