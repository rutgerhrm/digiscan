import os
import subprocess
import json
from urlparse import urlparse  # Adjust based on your Python version

def run_network_scan(target_url):
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Use urlparse to get the network location part (hostname) of the URL
    parsed_url = urlparse(target_url)
    target_hostname = parsed_url.hostname  # This strips the protocol and other parts
    safe_filename = target_hostname.replace(":", "_").replace("/", "_")
    xml_filename = "nmap_output_{}.xml".format(safe_filename)
    json_filename = "nmap_output_{}.json".format(safe_filename)
    xml_file_path = os.path.join(output_dir, xml_filename)
    json_file_path = os.path.join(output_dir, json_filename)

    # Ensure unique filenames
    file_counter = 1
    while os.path.exists(xml_file_path) or os.path.exists(json_file_path):
        xml_file_path = os.path.join(output_dir, "nmap_output_{}_{}.xml".format(safe_filename, file_counter))
        json_file_path = os.path.join(output_dir, "nmap_output_{}_{}.json".format(safe_filename, file_counter))
        file_counter += 1

    # Run nmap scan with XML output
    nmap_command = ["nmap", "-p", "80", target_hostname, "-oX", xml_file_path]
    try:
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print("Error running nmap: {}, {}".format(stderr, stdout))
            return None
    except Exception as e:
        print("Subprocess execution failed: {}".format(str(e)))
        return None

    # Convert XML to JSON using nmap-formatter
    formatter_command = ["nmap-formatter", "json", xml_file_path]
    try:
        process = subprocess.Popen(formatter_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            with open(json_file_path, 'w') as f:
                f.write(stdout)
            print("JSON output:", stdout)  # Print JSON to BurpSuite console
        else:
            print("Error converting XML to JSON: {}, {}".format(stderr, stdout))
            return None
    except Exception as e:
        print("Subprocess execution failed: {}".format(str(e)))
        return None

    return json_file_path

def parse_nmap_json(json_file_path):
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
        results = []
        hosts = data.get("Host", [])
        for host in hosts:
            ports = host.get("Port", [])
            for port in ports:
                if port.get("State", {}).get("State") == "open":
                    port_id = port.get("PortID")
                    service_name = port.get("Service", {}).get("Name", "unknown service")
                    result = {
                        "header": "Port {}".format(port_id),
                        "description": "Open port {} ({}) detected.".format(port_id, service_name),
                        "status": "warning",
                        "advice": "Consider reviewing the necessity of this service being exposed."
                    }
                    results.append(result)
        return results
    except Exception as e:
        print("Error parsing JSON output: {}".format(e))
        return []

