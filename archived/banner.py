# Define ANSI color codes
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
ORANGE = "\033[93m"

# Define the banner with colorized explanations
BANNER = f"""
{BOLD}
▓█████▄  ██▓ ▄████  ██▓  ██████ ▄████▄   ▄▄▄      ███▄    █ 
▒██▀ ██▌▓██▒██▒ ▀█▒▓██▒▒██    ▒▒██▀ ▀█  ▒████▄    ██ ▀█   █ 
░██   █▌▒██▒██░▄▄▄░▒██▒░ ▓██▄  ▒▓█    ▄ ▒██  ▀█▄ ▓██  ▀█ ██▒
░▓█▄   ▌░██░▓█  ██▓░██░  ▒   ██▒▓▓▄ ▄██▒░██▄▄▄▄██▓██▒  ▐▌██▒
░▒████▓ ░██░▒▓███▀▒░██░▒██████▒▒ ▓███▀ ░ ▓█   ▓██▒██░   ▓██░
 ▒▒▓  ▒ ░▓  ░▒   ▒ ░▓  ▒ ▒▓▒ ▒ ░ ░▒ ▒  ░ ▒▒   ▓▒█░ ▒░   ▒ ▒ 
 ░ ▒  ▒  ▒ ░ ░   ░  ▒ ░░ ░▒  ░ ░ ░  ▒     ▒   ▒▒ ░ ░░   ░ ▒░
 ░ ░  ░  ▒ ░ ░   ░  ▒ ░░  ░  ░ ░          ░   ▒     ░   ░ ░ 
   ░     ░       ░  ░        ░ ░ ░            ░  ░        ░ 
 ░                             ░                            

{RESET}
                                                - RutgerHrm

{GREEN}Groen{RESET}: Resultaat is "goed"
{ORANGE}Oranje{RESET}: Resultaat is "voldoende"
{RED}Rood{RESET}: Resultaat is "onvoldoende"
"""
