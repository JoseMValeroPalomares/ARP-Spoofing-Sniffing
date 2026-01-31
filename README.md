# 🛡️ Python ARP Spoofer Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![Status](https://img.shields.io/badge/Status-Educational-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Toolkit modular en **Python** para realizar **auditorías de red** mediante la técnica de **ARP Spoofing (Man-in-the-Middle)**.  
Incluye sniffers especializados para analizar tráfico **DNS** y **HTTP** (HTTPS en desarrollo).

---

## ⚠️ Aviso legal

> **DISCLAIMER**  
> Esta herramienta ha sido creada **exclusivamente con fines educativos y de pentesting ético** en redes **propias o con autorización explícita**.  
> El autor **no se hace responsable** del uso indebido de este software.

---

## 📚 Índice

- [Características](#-características)
- [Contenido](#-contenido)
- [Requisitos](#-requisitos)
- [Instalación](#️-instalación)
- [Uso](#-uso)
- [Roadmap](#-roadmap)
- [Autor](#-autor)

---

## ✨ Características

- Ataque **ARP Spoofing / MitM** automatizado
- Soporte para **Ethernet y Wi‑Fi**
- Configuración automática de:
  - `ip_forward`
  - `iptables`
- Restauración limpia de la red al finalizar
- Sniffing de:
  - 📡 Consultas **DNS**
  - 🌐 Tráfico **HTTP** (URLs y credenciales en claro)

---

## 📦 Contenido

| Archivo | Descripción |
|------|------------|
| `arp_spoofer.py` | Ejecuta el ataque MitM mediante ARP Spoofing |
| `sniffer_dns.py` | Captura dominios visitados por la víctima |
| `sniffer_http.py` | Captura URLs y credenciales HTTP (POST) |

---

## 🧰 Requisitos

- Linux (probado en Kali / Arch / Ubuntu)
- Python **3.x**
- Permisos de **root**
- Dependencias:
  - `scapy`
  - `argparse`
  - `subprocess`

---

## ⚙️ Instalación

```bash
git clone https://github.com/TU_USUARIO/Python-ARP-Spoofer-Toolkit.git
cd Python-ARP-Spoofer-Toolkit
pip3 install -r requirements.txt
```
---

## 🚀 Uso

El ataque requiere dos terminales.

🟢 Paso 1: Iniciar el ARP Spoofer (Terminal 1)

```bash
sudo python3 arp_spoofer.py -t <IP_VICTIMA> -i <INTERFAZ>
```
Ejemplo:
```bash
sudo python3 arp_spoofer.py -t 192.168.1.35 -i wlan0
```
---

🟢 Paso 2: Iniciar un Sniffer (Terminal 2)
Opción A: Ver dominios visitados (DNS)
```bash
sudo python3 sniffer_dns.py -i <INTERFAZ> -t <IP_VICTIMA>
```
Opción B: Capturar URLs y credenciales (HTTP)
```bash
sudo python3 sniffer_http.py -i <INTERFAZ> -t <IP_VICTIMA>
```

---

## 🛣️ Roadmap

 - Sniffer HTTPS (SNI / TLS metadata)

 - Exportación a archivos (.pcap, .txt)

 - Filtros avanzados

 - Modo silencioso

 - Detección automática de gateway

--- 

## 👨‍💻 Autor

Hecho por Pepe con 🐍 y Scapy
Proyecto educativo de ciberseguridad y redes

