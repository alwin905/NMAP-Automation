import subprocess
import xml.etree.ElementTree as ET
import json
import csv
import re
import os

# ISO 27001 Annex A mapping for all controls and sub-controls
ISO_27001_CONTROLS = {
    "vuln": "A.12.6.1 - Management of technical vulnerabilities",
    "ssl": "A.13.1.1 - Network Security",
    "ftp": "A.9.4.2 - Secure log-on procedures",
    "http": "A.14.1.2 - Secure application services",
    "dns": "A.13.2.1 - Network security controls",
    "policy": "A.5.1 - Information security policy",
    "internal_org": "A.6.1 - Internal organization",
    "mobile_teleworking": "A.6.2 - Mobile devices and teleworking",
    "prior_employment": "A.7.1 - Prior to employment",
    "during_employment": "A.7.2 - During employment",
    "termination_employment": "A.7.3 - Termination and change of employment",
    "asset_responsibility": "A.8.1 - Responsibility for assets",
    "info_classification": "A.8.2 - Information classification",
    "media_handling": "A.8.3 - Media handling",
    "access_control_business": "A.9.1 - Business requirements of access control",
    "user_access_management": "A.9.2 - User access management",
    "user_responsibilities": "A.9.3 - User responsibilities",
    "access_control_system": "A.9.4 - System and application access control",
    "cryptographic_controls": "A.10.1 - Cryptographic controls",
    "secure_areas": "A.11.1 - Secure areas",
    "equipment_security": "A.11.2 - Equipment security",
    "operational_procedures": "A.12.1 - Operational procedures and responsibilities",
    "malware_protection": "A.12.2 - Protection from malware",
    "backup": "A.12.3 - Backup",
    "logging_monitoring": "A.12.4 - Logging and monitoring",
    "software_control": "A.12.5 - Control of operational software",
    "audit_considerations": "A.12.7 - Information systems audit considerations",
    "network_security_management": "A.13.1 - Network security management",
    "information_transfer": "A.13.2 - Information transfer",
    "security_requirements": "A.14.1 - Security requirements of information systems",
    "security_development_support": "A.14.2 - Security in development and support processes",
    "test_data": "A.14.3 - Test data",
    "supplier_relationships": "A.15.1 - Information security in supplier relationships",
    "supplier_service_management": "A.15.2 - Supplier service delivery management",
    "incident_management": "A.16.1 - Management of information security incidents and improvements",
    "security_continuity": "A.17.1 - Information security continuity",
    "redundancies": "A.17.2 - Redundancies",
    "compliance": "A.18.1 - Compliance with legal and contractual requirements",
    "security_reviews": "A.18.2 - Information security reviews",
}

# Predefined Nmap script options
NMAP_SCRIPT_OPTIONS = [
    "vuln",
    "http-enum",
    "ftp-anon",
    "ssl-enum-ciphers",
    "http-sql-injection",
    "dns-brute",
    "http-headers",
    "Custom Nmap Command"  # Option for custom Nmap command
]

def display_nmap_script_options():
    """
    Display the predefined Nmap script options and let the user select multiple.
    """
    print("Select Nmap scripts to run (enter numbers separated by commas):")
    for i, option in enumerate(NMAP_SCRIPT_OPTIONS, start=1):
        print(f"{i}. {option}")
    choices = input("Enter your choices: ").strip()
    selected_scripts = []
    for choice in choices.split(","):
        try:
            selected_scripts.append(NMAP_SCRIPT_OPTIONS[int(choice) - 1])
        except (ValueError, IndexError):
            print(f"Invalid choice: {choice}")
    if not selected_scripts:
        print("No valid scripts selected. Exiting.")
        exit()
    return selected_scripts

def get_nmap_path():
    """
    Returns the path to nmap.exe located inside a subfolder 'nmap' in the script directory.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    nmap_path = os.path.join(script_dir, 'nmap', 'nmap.exe')  # Adjust path if necessary
    if not os.path.isfile(nmap_path):
        print(f"Error: nmap.exe not found at {nmap_path}.")
        exit(1)
    return nmap_path

def run_nmap_scan(command, output_file):
    """
    Run the Nmap scan with the provided command and return the output.
    """
    nmap_path = get_nmap_path()  # Get path to nmap.exe
    command = f'"{nmap_path}" {command}'  # Ensure proper execution of nmap.exe
    
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Scan completed successfully. Results saved in {output_file}.xml")
    else:
        print("Nmap scan failed.")
    return result.stdout

def map_iso_control(script_id, output):
    """
    Dynamically map vulnerabilities to ISO 27001 controls based on script ID and output.
    """
    for keyword, control in ISO_27001_CONTROLS.items():
        if keyword in script_id.lower() or keyword in output.lower():
            return control
    return "Not Mapped to ISO 27001"

def extract_cve_ids(output):
    """
    Extract CVE IDs from the Nmap script output (if present).
    """
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_ids = re.findall(cve_pattern, output)
    return ", ".join(cve_ids) if cve_ids else "None"

def get_cvss_score(cve_id):
    """
    Fetch CVSS score from NVD or other sources. (Placeholder function)
    You can replace this with an actual API call to the NVD or another CVE database.
    """
    # Example of using a mock mapping:
    cvss_scores = {
        "CVE-2021-44228": 10.0,  # Critical
        "CVE-2017-0144": 9.8,    # High
        # Add more CVE mappings here...
    }
    return cvss_scores.get(cve_id, None)

def classify_severity(output):
    """
    Classifies severity based on CVE IDs or keywords, with enhanced CVSS score-based classification.
    """
    # 1. Check for CVE IDs in the output
    if "CVE-" in output:
        cve_ids = extract_cve_ids(output)
        severity = "Medium"  # Default severity
        
        # 2. Check CVSS score for each CVE (If available, it can be integrated with an API or a mock mapping)
        for cve in cve_ids.split(", "):
            cvss_score = get_cvss_score(cve)  # Placeholder function to get CVSS score for a CVE
            
            if cvss_score:
                # Map CVSS score to severity
                if cvss_score >= 9.0:
                    severity = "Critical"
                elif cvss_score >= 7.0:
                    severity = "High"
                elif cvss_score >= 4.0:
                    severity = "Medium"
                else:
                    severity = "Low"
        
        return severity

    # 3. If no CVE found, classify based on keywords
    keywords = {
        "critical": "High",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "vulnerability": "Medium",
        "exploitable": "High",
        "remote code execution": "High",  # Example of specific exploit type that should be high
        "denial of service": "Medium",
    }

    for keyword, severity in keywords.items():
        if keyword in output.lower():
            return severity
    
    return "Unknown"

def parse_scan_results(xml_file):
    """
    Parse the Nmap scan results from the XML file.
    """
    vulnerabilities = []
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for host in root.findall("host"):
        ip_address = host.find("address").get("addr")
        for port in host.findall("ports/port"):
            port_id = port.get("portid")
            protocol = port.get("protocol")
            
            service_element = port.find("service")
            service = service_element.get("name", "Unknown Service") if service_element is not None else "Unknown Service"
            product = service_element.get("product", "Unknown Product") if service_element is not None else "Unknown Product"

            script_results = port.findall("script")

            if script_results:
                for script in script_results:
                    script_id = script.get("id")
                    output = script.get("output")
                    cve_ids = extract_cve_ids(output)
                    severity = classify_severity(output)

                    vulnerabilities.append({
                        "IP": ip_address,
                        "Port": port_id,
                        "Protocol": protocol,
                        "Service": service,
                        "Product": product,
                        "Script ID": script_id,
                        "Description": output,
                        "CVE IDs": cve_ids,
                        "Severity": severity,
                        "ISO 27001 Control": map_iso_control(script_id, output)
                    })
            else:
                vulnerabilities.append({
                    "IP": ip_address,
                    "Port": port_id,
                    "Protocol": protocol,
                    "Service": service,
                    "Product": product,
                    "Script ID": "N/A",
                    "Description": "No scripts ran for this port",
                    "CVE IDs": "None",
                    "Severity": "Low",
                    "ISO 27001 Control": "Not Applicable"
                })

    return vulnerabilities

def generate_json_report(vulnerabilities, output_file):
    """
    Generate a JSON report with the parsed vulnerabilities and ISO 27001 mapping.
    """
    with open(output_file + ".json", mode="w") as file:
        json.dump(vulnerabilities, file, indent=4)

def generate_csv_report(vulnerabilities, output_file):
    """
    Generate a CSV report with the parsed vulnerabilities and ISO 27001 mapping.
    """
    with open(output_file + ".csv", mode="w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=vulnerabilities[0].keys())
        writer.writeheader()
        writer.writerows(vulnerabilities)

def main():
    selected_scripts = display_nmap_script_options()
    
    if "Custom Nmap Command" in selected_scripts:
        custom_command = input("Enter your custom Nmap command (e.g., -A): ").strip()
    else:
        custom_command = " ".join(f"--script={script}" for script in selected_scripts if script != "Custom Nmap Command")
    
    target_ip = input("Enter the target IP address: ").strip()
    output_file = input("Enter the file name to save the output (without extension): ").strip()

    command = f"{custom_command} {target_ip} -oX {output_file}.xml"
    print(f"Running: {command}")
    
    run_nmap_scan(command, output_file)

    vulnerabilities = parse_scan_results(output_file + ".xml")
    
    generate_json_report(vulnerabilities, output_file)
    generate_csv_report(vulnerabilities, output_file)
    
    print(f"Reports generated: {output_file}.json and {output_file}.csv")

if __name__ == "__main__":
    main()
