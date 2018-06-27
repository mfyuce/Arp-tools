#!/usr/bin/env python

def missing_library(string):
    raise Exception("\nMissing %s Library\n" % (string))


try:
    import sys
except:
    missing_library("sys")
try:
    import signal
except:
    missing_library("signal")
try:
    from scapy.all import *
except:
    missing_library("scapy")
try:
    import netaddr
except:
    missing_library("netaddr")


def signal_handler(signal, frame):
    print('\n=================')
    print('Execution aborted')
    print('=================')
    os.system("kill -9 " + str(os.getpid()))
    sys.exit(1)


def signal_exit(signal, frame):
    sys.exit(1)


def usage():
    if len(sys.argv) < 3:
        print("\nUsage:")
        print("\tpython arp-scan.py -l <IPs>")
        print("\t<ips> is a single ip, range , or list of IPs (separated by \",\")\n")
        sys.exit(1)


def decode_netmask(network):
    ret = list()
    for ip in netaddr.IPNetwork(network):
        ret.append(scan_devices(str(ip)))
    return ret


def decode_file(filename):
    ipsfile = open(filename, "r")
    ret = list()
    for line in ipsfile:
        ret.append(scan_devices(line))
    return ret


def decode_enumeration(iplist):
    ret = list()
    for line in iplist:
        ret.append(scan_devices(line))
    return ret


def scan_devices(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff"), timeout=2, verbose=0)
    ret = list()
    for pair in ans:
        ret.append(pair)
        # print("%-20s%s" % (pair[1].psrc, pair[1].hwsrc))
    return ret


def check_root():
    if not os.geteuid() == 0:
        raise Exception("Run as root.")


def get_mac_from_ip(ip, subset):
    check_root()
    parameters = {subset: ip}

    if "/" in parameters[subset]:
        print("[*] Scanning subnet %s" % (parameters[subset]))
        print("\n%-20s%s" % ("IP", "MAC"))
        for s in decode_netmask(parameters[subset]):
            for pair in s:
                print("%-20s%s" % (pair[1].psrc, pair[1].hwsrc))
    elif "," in parameters[subset]:
        print("[*] Scanning list of IPs %s" % (parameters[subset]))
        print("\n%-20s%s" % ("IP", "MAC"))
        for s in decode_enumeration(parameters[subset]):
            for pair in s:
                print("%-20s%s" % (pair[1].psrc, pair[1].hwsrc))
    else:
        print("[*] Scanning Single IP %s" % (parameters[subset]))
        print("\n%-20s%s" % ("IP", "MAC"))
        for pair in scan_devices(parameters[subset]):
            print("%-20s%s" % (pair[1].psrc, pair[1].hwsrc))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    usage()

    print("\n[*] Scanning for active IPs")
    get_mac_from_ip(sys.argv[2], sys.argv[1] == "-l")
    print("")
