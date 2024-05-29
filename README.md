# DigiScan

DigiScan is a Burp Suite plugin designed to automate compliance checks against DigiD security norms for web applications.

## Overview

DigiScan provides automated security configuration validation against DigiD norms, enhancing audit efficiency for Hacksclusive. It helps ensure that web applications meet the Dutch governmental security requirements.

---

## Requirements

- Burp Suite (Professional or Community Edition).
- Jython Standalone.
- Go language.
- External tools:
  - [testssl.sh](https://testssl.sh/)
  - [ffuf](https://github.com/ffuf/ffuf)
  - [Wappalyzer](https://github.com/Webklex/wappalyzer)
  - [nmap-formatter](https://github.com/vdjagilev/nmap-formatter)

## Installation

To install DigiScan, follow these steps:

1. Download the latest release from the release page, or clone the repository:
   ```
   git clone https://github.com/hacksclusive/digiscan.git
   cd digiscan
   ```
   
2. Make the setup script executable and run it to install all requirements:
   ```
   chmod +x setup.sh
   ./setup.sh
   ```
   
3. Change the file paths to the config file and/or testssl.sh defined in `check_uwa05.py` and `check_upw03.py`
  
4. Open Burp Suite and navigate to the Extender tab.

5. Add the [Jython Standalone JAR](https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.4b2/jython-standalone-2.7.4b2.jar) in Burp Suite under Extensions > Extensions settings > Python Environment to be able to run Python extensions.

6. Load the main.py file under Extensions > Installed > Add.

---

## Usage

1. Open Burp Suite and navigate to the DigiScan tab.
2. Set your full target-URL (so including https:// prefix) in the input field.
3. Select the DigiD-norms you want to check.
4. Press "Start Scan" to begin the compliance checks.
5. View detailed results and potential advice in the DigiScan panel.

### Example

Include an example run of the tool.

## Key Checks

- **U/WA.05** - Reliability of Information: Ensures compliance with DigiD norms for TLS version, HSTS time, cipher suites, RSA key length, finite field group, elliptic curve, and OCSP stapling.
- **U/PW.03** - Restricting Unwanted Disclosure of Information: Checks HTTP headers, session cookies, and potential directory listings using testssl.sh FFUF to ensure proper security configurations.
- **U/PW.05** - Preventing Misuse of Management Functions: Validates that only allowed HTTP methods are enabled and checks their status codes to prevent unauthorized access.
- **C.09** - Preventing Outdated Web Components: Identifies and reports the technology stack and versions of a website using Wappalyzer and a simple banner grab to ensure no outdated components are used.

---

## Editing and adding Norms

The norms and corresponding advice are defined in a JSON configuration file. This approach centralizes configuration, making it easy to update norms without modifying the core code. You can simply search up the key you want to change, change the status and/or advice, and that's all. 

Adding a norm can require some more effort. Depending on it's complexity, it's as simple as copy pasting a different key and changing it's details, to adding some compliance checks in it's own designated module.

### Example JSON Configuration

```json
{
    "TLS1_2": {
        "friendly_name": "TLS 1.2",
        "not offered": {
            "status": "fail",
            "advice": "TLS 1.2 should be enabled"
        },
        "offered": {
            "status": "warning",
            "advice": "Consider disabling TLS 1.2 if not strictly needed"
        }
    },
    "TLS1_3": {
        "friendly_name": "TLS 1.3",
        "not offered": {
            "status": "fail",
            "advice": "TLS 1.3 should be enabled"
        },
        "offered with final": {
            "status": "pass",
            "advice": "TLS 1.3 is correctly offered with final"
        }
    }
}
```

---

## About

Developed as part of a thesis project at Hanze UAS, DigiScan aims to reduce the time and complexity involved in manual DigiD security assessments.

## Credits

- **Author**: Rutger Harmers
