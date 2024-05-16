import subprocess

def run_network_scan(host):
    # Modify the host if it contains protocols
    if 'https://' in host:
        host = host.replace('https://', '')
    elif 'http://' in host:
        host = host.replace('http://', '')

    command = ["nmap", host]
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if stderr:
            return {"error": "Error executing nmap: " + stderr}
        return parse_nmap_output(stdout)
    except Exception as e:
        return {"error": "Failed to run nmap: " + str(e)}

def parse_nmap_output(output):
    results = []
    lines = output.split('\n')
    for line in lines:
        if "Nmap scan report for" in line or "open" in line and "/tcp" in line:
            results.append({"description": line.strip(), "status": "info"})
    return results
