import os
import subprocess
import json
import logging
from urlparse import urlparse

# Set up logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def run_network_scan(target_url):
    """
    Runs both TCP and UDP network scans on the target URL and saves the output to JSON files.
    
    Parameters:
    target_url (str): The URL of the target to scan.

    Returns:
    tuple: Paths to the TCP and UDP JSON output files.
    """
    # Set up directories and filenames
    output_dir = "/home/kali/Desktop/Hacksclusive/DigiScan/output"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logging.debug('Output directory created at: %s' % output_dir)

    parsed_url = urlparse(target_url)
    target_hostname = parsed_url.hostname or target_url

    if target_hostname.startswith("www."):
        target_hostname = target_hostname[4:]

    safe_filename = target_hostname.replace(":", "_").replace("/", "_")
    tcp_xml_filename = "nmap_tcp_output_{}.xml".format(safe_filename)
    udp_xml_filename = "nmap_udp_output_{}.xml".format(safe_filename)
    tcp_json_filename = "nmap_tcp_output_{}.json".format(safe_filename)
    udp_json_filename = "nmap_udp_output_{}.json".format(safe_filename)

    tcp_xml_file_path = os.path.join(output_dir, tcp_xml_filename)
    udp_xml_file_path = os.path.join(output_dir, udp_xml_filename)
    tcp_json_file_path = os.path.join(output_dir, tcp_json_filename)
    udp_json_file_path = os.path.join(output_dir, udp_json_filename)

    # Execute TCP and UDP scans
    execute_scan(["nmap", "-p-", target_hostname, "-oX", tcp_xml_file_path], tcp_xml_file_path, tcp_json_file_path, "TCP")
    
    execute_scan(["sudo", "nmap", "--resolve-all", "--top-ports 1000", "-sU", "-sV", "-T4", "--max-retries", "1", target_hostname, "-oX", udp_xml_file_path], udp_xml_file_path, udp_json_file_path, "UDP")

    return tcp_json_file_path, udp_json_file_path

def execute_scan(nmap_command, xml_file_path, json_file_path, scan_type):
    """
    Executes the nmap scan and converts the XML output to JSON.
    
    Parameters:
    nmap_command (list): The nmap command to execute.
    xml_file_path (str): Path to the XML output file.
    json_file_path (str): Path to the JSON output file.
    scan_type (str): Type of scan being performed (TCP/UDP).
    """
    try:
        logging.debug('Running command: %s' % ' '.join(nmap_command))
        process = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        logging.debug('%s scan output: %s' % (scan_type, stdout))
        if process.returncode != 0:
            logging.error("Error running %s nmap: %s, %s" % (scan_type, stderr, stdout))
            return None
    except Exception as e:
        logging.error("%s Subprocess execution failed: %s" % (scan_type, str(e)))
        return None

    # Convert XML to JSON
    if os.path.exists(xml_file_path):
        convert_xml_to_json(xml_file_path, json_file_path, scan_type)
    else:
        logging.error('XML file not found for %s scan: %s' % (scan_type, xml_file_path))

def convert_xml_to_json(xml_file_path, json_file_path, scan_type):
    """
    Converts the nmap XML output to JSON format.
    
    Parameters:
    xml_file_path (str): Path to the XML output file.
    json_file_path (str): Path to the JSON output file.
    scan_type (str): Type of scan being performed (TCP/UDP).
    """
    formatter_command = ["nmap-formatter", "json", xml_file_path]
    try:
        logging.debug('Running formatter command: %s' % ' '.join(formatter_command))
        process = subprocess.Popen(formatter_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            with open(json_file_path, 'w') as f:
                f.write(stdout)
            os.remove(xml_file_path)
            logging.debug("%s JSON created and XML deleted" % scan_type)
        else:
            logging.error("Error converting %s XML to JSON: %s, %s" % (scan_type, stderr, stdout))
    except Exception as e:
        logging.error("%s Formatter Subprocess execution failed: %s" % (scan_type, str(e)))

def parse_nmap_json(json_file_path, scan_type):
    """
    Parses the nmap JSON output and extracts relevant port scan information.
    
    Parameters:
    json_file_path (str): Path to the JSON output file.
    scan_type (str): Type of scan being parsed (TCP/UDP).

    Returns:
    list: Parsed results including open ports and relevant advice.
    """
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)

        results = []
        hosts = data.get("Host", [])

        for host in hosts:
            ports = host.get("Port", [])
            for port in ports:
                port_state = port.get("State", {}).get("State")
                if "open" in port_state and port.get("State", {}).get("Reason") != "no-response":
                    port_id = port.get("PortID")
                    service_info = port.get("Service", {})
                    service_name = service_info.get("Name", "unknown service")
                    description = "Port {} ({}) is open.".format(port_id, service_name)
                    advice = "Verify necessity and security configurations of this service."

                    result = {
                        "header": "Port {}".format(port_id),
                        "description": description,
                        "status": "pass",
                        "advice": advice,
                        "scan_type": scan_type
                    }
                    results.append(result)

        if not results and scan_type == "UDP":
            results.append({
                "header": "No Open Ports",
                "description": "No open UDP ports found.",
                "status": "info",
                "advice": "No action needed unless expecting open ports.",
                "scan_type": scan_type
            })

        return results
    except Exception as e:
        logging.error("Error parsing JSON output: %s" % str(e))
        return []
