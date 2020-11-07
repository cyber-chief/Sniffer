

import datetime
import socket
import time
import os
import geoip
from scapy.layers.inet import *
from scapy.sendrecv import sniff


def monitoringForVisualization(packet):
    time = datetime.datetime.now()

    if packet.hasLayer(ICMP):
        #ICMP packet
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print(str("[") + str(time) + str("]") + "  " + "ICMP-IN:{}".format(
                len(packet[ICMP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(
                packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)
        if socket.gethostbyname(socket.gethostname()) == packet[IP].src:
            print(str("[") + str(time) + str("]") + "  " + "ICMP-OUT:{}".format(
                len(packet[ICMP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(
                packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)
    if packet.hasLayer(TCP):
        #TCP packet
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print(str("[") + str(time) + str("]") + "  " + "TCP-IN:{}".format(
                len(packet[TCP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)
        if socket.gethostbyname(socket.gethostname()) == packet[IP].src:
            print(str("[") + str(time) + str("]") + "  " + "TCP-OUT:{}".format(
                len(packet[TCP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)
    if packet.hasLayer(UDP):
        #UDP packet
        if socket.gethostbyname(socket.gethostname()) == packet[IP].dst:
            print(str("[") + str(time) + str("]") + "  " + "UDP-IN:{}".format(
                len(packet[UDP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(
                packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)
        if socket.gethostbyname(socket.gethostname()) == packet[IP].src:
            print(str("[") + str(time) + str("]") + "  " + "UDP-OUT:{}".format(
                len(packet[UDP])) + " Bytes" + "" + "SRC-MAC:" + str(packet.src) + "" + "DST-MAC:" + str(
                packet.dst) + "" + "SRC-PORT:" + str(packet.sport) + "" + "DST-PORT:" + str(
                packet.dport) + "" + "SRC-IP:" + str(
                packet[IP].src) + "" + "DST-IP:" + str(packet[IP].dst) + "  " + "Location:" + geoip.geolite2.lookup(
                packet[IP].src).timezone)

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    sniff(prn=monitoringForVisualization)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
