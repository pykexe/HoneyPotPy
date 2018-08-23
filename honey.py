import socket, os, sys, getopt
import logging
from struct import *
import argparse
import os


class HoneyPotPy():

    def __init__(self, port, banner='Tomcat'):
        self.port = port
        self.banner = banner

    def create_socket(self, port):
        if not os.getuid() == 0:
            sys.exit("[+] This script needs root.. to open a socket.. ")
        block = True
        ls, s = socket.socket(socket.AF_INET, socket.SOCK_STREAM), socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        ls.bind(('', int(self.port)))
        ls.listen(5)
        while True:
            packet = s.recvfrom(500)
            packet = packet[0]
            iph = packet[0:20]
            iph = unpack('!BBHHHBBH4s4s' , iph)
            version = iph[0] >> 4
            ihl = iph[0] & 0xF
            iph_length = ihl * 4
            s_addr,d_addr = socket.inet_ntoa(iph[8]), socket.inet_ntoa(iph[9]);
            tcp_header = packet[iph_length:iph_length+20]
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            dest_port,length = tcph[1], tcph[4] >> 4
            if (str(dest_port) == str(self.port)):
                print("[+] Invader detected: {}".format(s_addr))
                print("[+] Blocking ip...")
                os.system("iptables -A INPUT -s " + str(s_addr) + " -j DROP")
            

parser = argparse.ArgumentParser(
    'description: simple HoneyPot to use with your ip tables.. to find nmap scans..')
parser.add_argument('-p', '--port', help="port to use with",
                    default='localhost')
var = parser.parse_args()

if __name__ == '__main__':
    port = var.port
    potObj = HoneyPotPy(port)
    potObj.create_socket(port)
