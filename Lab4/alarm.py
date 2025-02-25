#!/usr/bin/python3

from scapy.all import *
import argparse
import urllib.request

counter = 0


#TARGET_IP = "" #use for testing only
SMB_PORTS = [139, 445]
RDP_PORT = 3389
VNC_PORT = 5900

def detect_smb_vnc_rdp_scan(packet):
    #with urllib.request.urlopen('https://api.ipify.org') as response:
    #    external_ip = response.read().decode('utf-8')
    if IP in packet and TCP in packet and packet[IP].dst == external_ip:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if dst_port in SMB_PORTS:
            print(f"ALERT: SMB scan detected from {src_ip} to port {dst_port}")
        elif dst_port == RDP_PORT:
            print(f"ALERT: RDP scan detected from {src_ip}")
        elif dst_port == VNC_PORT:
            print(f"ALERT: VNC scan detected from {src_ip}")

def detect_fin_scan(packet):
    if packet.haslayer(TCP):
        if packet[TCP].flags == 1:  # FIN flag is set (0x01)
            print(f"FIN scan detected from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")

def detect_null_scan(packet):
    if packet.haslayer(TCP):
        if packet[TCP].flags == 0:  # No flags set
            print(f"NULL scan detected from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")

def detect_nikto(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        if "Nikto" in payload:
            print(f"ALERT: Nikto scan detected from {packet[IP].src} (TCP port {packet[TCP].sport})!")


def detect_xmas_scan(packet):
    if packet.haslayer(TCP):
        if packet[TCP].flags == 41:  # FIN, PSH, and URG flags set (0x29 or 41 in decimal)
            print(f"XMAS scan detected from {packet[IP].src}:{packet[TCP].sport} to {packet[IP].dst}:{packet[TCP].dport}")


def packetcallback(packet):
  
  try:
    if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            
            # HTTP password detection
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                if "password=" in payload.lower():
                    print(f"HTTP password detected: {payload}")
                if "authorization: basic" in payload.lower():
                    print(f"HTTP password detected: {payload}")
            
            # FTP password detection
            elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                if "USER" in payload.upper():
                    print(f"FTP credential detected: {payload}")
                if "PASS" in payload.upper():
                    print(f"FTP credential detected: {payload}")
            
            # IMAP password detection
            elif packet[TCP].dport == 143 or packet[TCP].sport == 143:
                if "LOGIN" in payload.upper() or "AUTHENTICATE" in payload.upper():
                    print(f"IMAP credential detected: {payload}")
            
            # Telnet password detection
            elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                if "login:" in payload.lower() or "password:" in payload.lower():
                    print(f"Telnet credential detected: {payload}")
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts
    detect_fin_scan(packet)
    detect_null_scan(packet)
    detect_nikto(packet)
    detect_xmas_scan(packet)
    detect_smb_vnc_rdp_scan(packet)
    
    if packet[TCP].dport == 80:
      if counter == 0:
          print("HTTP (web) traffic detected!")
          counter = 1
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass
counter = 0
counter2 = 0
while counter2 != 1:
    with urllib.request.urlopen('https://api.ipify.org') as response:
        external_ip = response.read().decode('utf-8')
        counter2 = 1


# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
