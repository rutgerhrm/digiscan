# DigiScan
DigiScan is Burp Suite plugin designed to automate compliance checks against DigiD security norms for web applications.

## Overview
DigiScan provides automated security configuration validation against DigiD norms, enhancing audit efficiency for Hacksclusive. It helps ensure that web applications meet the Dutch governmental security requirements.

---

## Requirements
- Java Runtime Environment (JRE) 8 or later.
- Burp Suite (Professional or Community Edition).
- External tools:
  - testssl.sh
  - ffuf
  - Wappalyzer
  - MEER TOEVOEGEN

## Installation
To install DigiScan:

1. Download the latest release from the [release page](https://github.com/hacksclusive/digiscan/releases/), or try to:
2. Clone the repository:
   ```bash
   git clone https://github.com/rutgerhrm/digiscan.git
   ```
3. Open Burp Suite and navigate to the Extender tab.
4. Load the run file `main.py` under Burp Extensions > Add.

---

## Usage
1. Open Burp Suite and navigate to the DigiScan tab.
2. Set your target and scan settings in the DigiScan tab.
3. Press "Start Scan" to begin the compliance checks.
4. View detailed results and potential advice in the DigiScan panel.

### Example
Hier komt een voorbeeld run van de tool

## Key Checks
- U/WA.05 - 
- U/PW.03 -
- U/PW.05 -
- C.09 -

---

## About
Developed as part of a thesis project at Hanze UAS, DigiScan aims to reduce the time and complexity involved in manual DigiD security assessments.

## Credits
- **Author**: Rutger Harmers
