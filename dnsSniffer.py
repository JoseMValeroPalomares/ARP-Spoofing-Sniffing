#!/usr/bin/env python3 
# Autor = Pepe >:)

import scapy.all as scapy
import argparse
import sys
from termcolor import colored

def get_arguments():
    parser = argparse.ArgumentParser(description="DNS Sniffer - Captura peticiones de dominio ")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Interfaz de red (ej: wlan0, eth0)")
    parser.add_argument("-t", "--target", required=True, dest="target", help="IP de la víctima")
    args = parser.parse_args()

    return args.interface, args.target

def process_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        try:
            domain = packet[scapy.DNSQR].qname.decode('utf-8')

            if domain.endswith('.'):
                    domain = domain[:-1]

            print(colored(f"[+] Sitio visitado: {domain}", "cyan"))
        
        except Exception:
            pass

def main():
    if len(sys.argv) < 2:
        print(colored("[!] Uso: sudo python3 dnsSniffer.py -i <interfacz>", "red"))
        sys.exit(1)
    
    interface, target = get_arguments()

    print(colored(f"\n--- DNS Sniffer Activo (Interfaz: {interface}) ---", "white", attrs=['bold']))
    print(colored("[*] Esperando consultas DNS de {target} (Ctrl+C para salir)\n", "blue"))

    bpf_filter = f"udp port 53 and src host {target}"

    try:
        scapy.sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=0)
    
    except KeyboardInterrupt:
        print(colored("\n[!] Sniffer detenido.", "yellow"))

if __name__ == "__main__":
    main()