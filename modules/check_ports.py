import os
import subprocess
import json
from urlparse import urlparse  # Adjust based on your Python version

def run_network_scan(target_url):
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    parsed_url = urlparse(target_url)
    target_hostname = parsed_url.hostname
    safe_filename = target_hostname.replace(":", "_").replace("/", "_")
    xml_filename = "nmap_output_{}.xml".format(safe_filename)
    json_filename = "nmap_output_{}.json".format(safe_filename)
    xml_file_path = os.path.join(output_dir, xml_filename)
    json_file_path = os.path.join(output_dir, json_filename)

    file_counter = 1
    while os.path.exists(xml_file_path) or os.path.exists(json_file_path):
        xml_file_path = os.path.join(output_dir, "nmap_output_{}_{}.xml".format(safe_filename, file_counter))
        json_file_path = os.path.join(output_dir, "nmap_output_{}_{}.json".format(safe_filename, file_counter))
        file_counter += 1

    nmap_command = ["nmap", "-p", "80", "-sV", target_hostname, "-oX", xml_file_path]
    try:
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            print("Error running nmap: {}, {}".format(stderr, stdout))
            return None
    except Exception as e:
        print("Subprocess execution failed: {}".format(str(e)))
        return None

    formatter_command = ["nmap-formatter", "json", xml_file_path]
    try:
        process = subprocess.Popen(formatter_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            with open(json_file_path, 'w') as f:
                f.write(stdout)
            os.remove(xml_file_path)  
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
        
        print("Parsed JSON data: {}".format(data))

        results = []
        hosts = data.get("Host")

        if not hosts:
            print("No hosts found in the JSON data.")
            return results

        if not isinstance(hosts, list):
            raise ValueError("Unexpected JSON structure for 'Host'")

        for host in hosts:
            ports = host.get("Port", [])

            if not ports:
                print("No 'Port' key found for host: {}".format(host))
                continue
            
            if not isinstance(ports, list):
                raise ValueError("Unexpected JSON structure for 'Port'")
            
            for port in ports:
                if port.get("State", {}).get("State") == "open":
                    port_id = port.get("PortID")
                    service_info = port.get("Service", {})
                    service_name = service_info.get("Name", "unknown service")
                    service_product = service_info.get("Product", "")
                    service_version = service_info.get("Version", "")
                    service_extrainfo = service_info.get("ExtraInfo", "")

                    description = f"Open port {port_id} ({service_name}) detected."
                    if service_product:
                        description += f" Product: {service_product}"
                    if service_version:
                        description += f" Version: {service_version}"
                    if service_extrainfo:
                        description += f" Extra Info: {service_extrainfo}"
                    
                    result = {
                        "header": f"Port {port_id}",
                        "description": description,
                        "status": "warning",
                        "advice": "Consider reviewing the necessity of this service being exposed."
                    }
                    results.append(result)

        print("Results: {}".format(results))
        return results
    except Exception as e:
        print("Error parsing JSON output: {}".format(e))
        return []
