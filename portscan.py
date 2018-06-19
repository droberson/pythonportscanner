#!/usr/bin/env python3

""" portscan.py - by Daniel Roberson (@dmfroberson)
TODO:
      - verbose output option
      - option to disable DNS resolution
      - ipv6 support
      - randomize hosts/ports
      - do stuff to open ports? (like rdpfingerprint, telnetfp, ...)
      - progress report?
      - ability to scan slower than full throttle.
      - output strategies:
        - plain text/stdout
        - plain text to a logfile
        - CSV
      - if port is set to "all", do 1-65535
"""

import os
import sys
import struct
import string
import socket
import argparse
from threading import Thread
from queue import Queue


IP_QUEUE = Queue()
OPEN_QUEUE = Queue()


def validate_ip_address(ip_address):
    """ validate_ip_address() -- Validate an IP address.

    Args:
        ip_address (str) - IP address to validate.

    Returns:
        True if ip_address is valid.
        False if ip_address is not valid.
    """
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def scan_port(host, port, delay=1):
    """ scan_port() - Determine if a TCP port is open or not.

    Args:
        host (str) - Host to connect to.
        port (int) - Port to connect to.
        delay (int) - Timeout in seconds. Default = 1.

    Returns:
        True if port is open on host.
        False if port is not open on host.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(delay)
    try:
        sock.connect((host, port))
    except Exception as exc:
        # TODO output exception info if verbose
        return False
    # TODO run secondary scanning methods against open sockets
    sock.close()
    return True


def thread_proc(thread_id, queue):
    """ thread_proc() - Thread handling process.

    Args:
        thread_id (int) - Thread number.
        queue (Queue) - Queue of tasks.

    Returns:
        Nothing.
    """
    while True:
        host, port = queue.get()
        # TODO output this if verbose
        #print("Thread %d: %s:%s" % (thread_id, host, str(port)))
        if scan_port(host, port):
            OPEN_QUEUE.put((host, port))
        queue.task_done()


def valid_port(port):
    """ valid_port() - Validate a port number.

    Args:
        port (int) - Port number to validate.

    Returns:
        True if port is a valid port number.
        False if port is not a valid port number.
    """
    try:
        if int(port) > 0 and int(port) < 65536:
            return True
    except ValueError:
        return False
    return False


def build_portlist(portlist):
    """ build_portlist() - Build list of ports from Nmap syntax.

    Args:
        portlist (str) - Nmap notation port list. Ex: 1-1024,5555,8080

    Returns:
        Unique list of ports derived from portlist on success.
        Empty list if portstring is invalid.
    """
    final = []
    allowed = set(string.digits + "-,")
    if (set(portlist) <= allowed) is False:
        return list()
    ports = portlist.split(",")
    for port in ports:
        if "-" in str(port):
            tmp = port.split("-")
            if len(tmp) != 2:
                return list()
            if int(tmp[0]) > int(tmp[1]):
                return list()
            final += range(int(tmp[0]), int(tmp[1]) + 1)
            continue
        final.append(int(port))
    if all(valid_port(port) for port in final) is True:
        return list(set(final))
    return list()


def build_portlist_from_services(protocol="all"):
    """ build_portlist_from_services() - Make a port list from the services file.

    Args:
        protocol (str) - "tcp", "udp", or "all". Default is "all"

    Returns:
        List of port numbers derived from /etc/services
    """
    valid_protocols = ["tcp", "udp"]
    if protocol != "all" and protocol not in valid_protocols:
        raise ValueError("Invalid protocol: %s" % protocol)

    final = []

    if sys.platform == "win32":
        services_file = r"C:\windows\system32\drivers\etc\services"
    else:
        services_file = "/etc/services"

    with open(services_file) as services:
        for line in services:
            if line.startswith("#") or line.isspace():
                continue
            port, proto = line.split()[1].split("/")
            if proto == protocol or protocol == "all":
                final.append(int(port))

    return list(set(final))


def hostname_to_ip(hostname):
    """ hostname_to_ip() - Resolve a hostname, returning an IP address.

    Args:
        hostname (str) - Hostname to resolve.

    Returns:
        String containing IP address in dotted quad notation.
    """
    try:
        resolved = socket.getaddrinfo(hostname, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    return resolved[0][4][0]


def valid_ipv4_address(ip_address):
    """ valid_ipv4_address() - Validate an IPv4 address.

    Args:
        ip_address (str) - IP address to verify.

    Returns:
        True if ip_address is a valid IPv4 address.
        False if ip_address is not a valid IPv4 address.
    """
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def ip_to_long(ip_address):
    """ ip_to_long() - Concert IP address to decimal.

    Args:
        ip_address (str) - IP address in dotted quad notation.

    Returns:
        Decimal representation of ip_address.
    """
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    """ long_to_ip() - Convert decimal number to IP address.

    Args:
        ip_address (int) - Number representing an IP address.

    Returns:
        String containing IP address in dotted quad notation.
    """
    tmp = struct.pack("!L", ip_address)
    return socket.inet_ntoa(tmp)


def build_iplist(iplist):
    """ build_iplist() - Build list of IP addresses from CIDR network notation.

    Args:
        iplist (str) - CIDR notation network. Ex: 192.168.0.0/24
                     - Note: this will also take single IP addresses.

    Returns:
        A list of IPs on success.
        An empty list on failure.
    """
    final = []
    if "/" in iplist:
        network, cidrmask = iplist.split("/")
        if int(cidrmask) < 0 or int(cidrmask) > 32:
            # invalid CIDR mask
            return list()
        if not valid_ipv4_address(network):
            # invalid network address
            return list()

        inverse = 0xffffffff << (32 - int(cidrmask)) & 0xffffffff
        first = ip_to_long(network) & inverse
        last = first | (~inverse & 0xffffffff)

        for ip in range(first + 1, last):
            final.append(long_to_ip(ip))
        return final

    elif valid_ipv4_address(iplist):
        final.append(iplist)
    else:
        # TODO: check if we should resolve
        resolved = hostname_to_ip(iplist)
        if resolved:
            final.append(resolved)
    return final


def parse_blacklist(filename):
    """ parse_blacklist() - Parse blacklist file.

    Args:
        filename (str) - Path to blacklist.

    Returns:
        Unique list of IP addresses on success.
        Exits with EX_USAGE if blacklist cannot be read.

    Example blacklist file:

        # This is a comment
        10.10.10.10
        192.168.0.0/24
    """
    final = []
    try:
        with open(filename, "r") as blacklist:
            for line in blacklist:
                if line.isspace() or line.startswith("#"):
                    continue
                final += build_iplist(line.rstrip())
    except FileNotFoundError as exc:
        print("[-] Unable to open blacklist %s: %s" % (filename, exc))
        exit(os.EX_USAGE)
    except PermissionError as exc:
        print("[-] Unable to open blacklist %s: %s" % (filename, exc))
        exit(os.EX_USAGE)
    return list(set(final))


def main():
    """ main() - Handle CLI arguments and execute a port scan.

    Args:
        None.

    Returns:
        Nothing.
    """
    description = "portscan.py by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "hosts",
        action="store",
        help="host(s) to connect to. ex: 127.0.0.1, 10.0.0.0/8, ...")
    parser.add_argument(
        "ports",
        action="store",
        help="port(s) to connect to. ex: 22, 1-1024, -",
        nargs="?")
    parser.add_argument(
        "-F",
        "--fast",
        action="store_true",
        required=False)
    parser.add_argument(
        "-t",
        "--threads",
        help="number of threads to use during scanning.",
        required=False,
        default=8)
    parser.add_argument(
        "-b",
        "--blacklist",
        help="file containing off-limits IP addresses or CIDR ranges",
        required=False)
    args = parser.parse_args()

    # Build port list from supplied CLI args
    if not args.ports and not args.fast:
        parser.print_help()
        print("[-] Must specify port range or use -F flag.")
        exit(os.EX_USAGE)

    if args.ports and args.fast:
        parser.print_help()
        print("[-] Cannot use -F and specify a port range.")
        exit(os.EX_USAGE)

    if args.ports:
        ports = build_portlist(args.ports)
        if not ports:
            parser.print_help()
            print("[-] Invalid port range: %s" % args.ports)
            exit(os.EX_USAGE)

    if args.fast:
        ports = build_portlist_from_services()

    # Build host list from supplied CLI args, accounting for blacklist.
    hosts = build_iplist(args.hosts)
    if not hosts:
        parser.print_help()
        print("[-] Invalid host(s): %s" % args.hosts)
        exit(os.EX_USAGE)

    blacklist = []
    if args.blacklist:
        blacklist = parse_blacklist(args.blacklist)
    hosts = [host for host in hosts if not in blacklist]

    # Add scan targets to the queue.
    # TODO: option to shuffle this
    for host in hosts:
        for port in ports:
            IP_QUEUE.put((host, port))

    total_hosts = len(hosts)
    total_ports = len(ports)
    total_scanned = IP_QUEUE.qsize()

    # Start worker threads
    for thread in range(int(args.threads)):
        worker = Thread(target=thread_proc, args=(thread, IP_QUEUE))
        worker.setDaemon(True)
        worker.start()

    # Wait for queue
    IP_QUEUE.join()

    # Report
    print("Scanned %d ports on %d hosts. %d open" % \
        (total_scanned, total_hosts, OPEN_QUEUE.qsize()))
    while not OPEN_QUEUE.empty():
        print(OPEN_QUEUE.get())


if __name__ == "__main__":
    main()

