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

1. Download the latest release from the releases page.
2. Clone the repository:
   ```git clone https://github.com/rutgerhrm/digiscan.git```
3. Navigate to the cloned directory:
   ```cd digiscan```
4. Load the extension in Burp Suite via the Extender tab.

---

## Usage
1. Open Burp Suite and navigate to the Extender tab.
2. Install DigiScan as a Java extension.
3. Set your target settings in the DigiScan tab.
4. Press "Start Scan" to begin the compliance checks.
5. View detailed results in the DigiScan panel.

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
