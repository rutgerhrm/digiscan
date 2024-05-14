import subprocess

def run_server_check(target_url):
    # Curl command to fetch the server header
    curl_command = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%header{server}"  # Fetching the server header directly
    ]

    # Add the target URL to the command
    curl_command.append(target_url)

    process = subprocess.Popen(curl_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = process.communicate()

    server_header = stdout.strip()

    results = []
    if server_header:
        results.append({
            'description': 'Server Information',
            'status': 'warning',  
            'advice': 'Server header is visible, which could reveal sensitive information about the server configuration.',
            'found': 'Server: {}'.format(server_header)  
        })
    else:
        results.append({
            'description': 'Server Information',
            'status': 'pass',  
            'advice': 'The HTTP banner does not reveal server info',
            'found': 'No server header present'
        })

    return results
