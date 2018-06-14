#!/usr/bin/env python3

"""
TODO:
      - verbose output option
      - option to disable DNS resolution
      - ipv6 support
      - randomize hosts/ports
      - docstrings, pylint warnings, ...
      - do stuff to open ports? (like rdpfingerprint, telnetfp, ...)
      - progress report?
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
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def scan_port(host, port, delay=1):
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


def thread_proc(x, queue):
    while True:
        host, port = queue.get()
        # TODO output this if verbose
        #print("Thread %d: %s:%s" % (x, host, str(port)))
        if scan_port(host, port):
            OPEN_QUEUE.put((host, port))
        queue.task_done()


def valid_port(port):
    try:
        if int(port) > 0 and int(port) < 65536:
            return True
    except ValueError:
        return False
    return False


def build_portlist(portlist):
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
    valid_protocols = ["tcp", "udp"]

    if protocol != "all" and protocol not in valid_protocols:
        raise ValueError("Invalid protocol: %s" % protocol)

    final = []

    if sys.platform == "win32":
        services_file = "C:\windows\system32\drivers\etc\services"
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
    try:
        resolved = socket.getaddrinfo(hostname, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    return resolved[0][4][0]


def valid_ipv4_address(ip_address):
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def ip_to_long(ip_address):
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    tmp = struct.pack("!L", ip_address)
    return socket.inet_ntoa(tmp)


def build_iplist(iplist):
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


def main():
    description = "portscan.py by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "hosts",
        action = "store",
        help = "host(s) to connect to. ex: 127.0.0.1, 10.0.0.0/8, ...")
    parser.add_argument(
        "ports",
        action = "store",
        help = "port(s) to connect to. ex: 22, 1-1024, -",
        nargs = "?")
    parser.add_argument(
        "-F",
        "--fast",
        action = "store_true",
        required = False)
    parser.add_argument(
        "-t",
        "--threads",
        required = False,
        default = 8)
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

    # Build host list from supplied CLI args
    hosts = build_iplist(args.hosts)
    if not hosts:
        parser.print_help()
        print("[-] Invalid host(s): %s" % args.hosts)
        exit(os.EX_USAGE)

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
        (total_scanned, total_hosts,OPEN_QUEUE.qsize()))
    while not OPEN_QUEUE.empty():
        print(OPEN_QUEUE.get())


if __name__ == "__main__":
    main()

