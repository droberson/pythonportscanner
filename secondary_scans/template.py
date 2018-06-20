"""
Template for a new secondary scanning module. These must be in this directory
and be named mod_NAMEHERE.py
"""

# import this for SCANNERS and other global settings/variables.
from .secondary import *


# Define a function to run. host and port are required arguments that
# will contain the IP address/hostname to connect to and the port.
def function_ssh(host, port):
    print("This is probably an SSH server.")

# Register this function on the specified port. If a host has port 22 open,
# it will run function_ssh(host, port) upon discovery by the main scanner.
SCANNERS.append((22, function_ssh))

