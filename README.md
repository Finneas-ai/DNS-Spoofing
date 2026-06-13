# 🕵️ DNS Spoofing mediante ARP Poisoning
[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-required-orange)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-Educational-green)]()
[![Video Demo](https://img.shields.io/badge/Demo-YouTube-red?logo=youtube)](https://www.youtube.com/playlist?list=PLOKfCoa5pjgc)

---

## 🎬 Demo

📺 [Ver playlist de demostración](https://www.youtube.com/playlist?list=PLOKfCoa5pjgc)

---

## 📋 Descripción

Este laboratorio demuestra cómo un atacante puede manipular las respuestas del **Sistema de Nombres de Dominio (DNS)** para redirigir a los usuarios hacia direcciones IP bajo su control.

Mediante la falsificación de registros DNS, combinada con **ARP Poisoning**, el atacante se posiciona como intermediario del tráfico y responde a las consultas DNS de la víctima antes que el servidor legítimo, redirigiendo al usuario hacia una página web falsa diseñada para capturar credenciales.

---

## 🎯 Objetivos

### Objetivo del Laboratorio
Comprender el funcionamiento del ataque **DNS Spoofing** y analizar cómo la falsificación de registros DNS puede afectar la integridad de las comunicaciones, permitiendo el acceso a sitios falsificados, la captura de credenciales y la alteración del tráfico de red.

### Objetivo del Script
Interceptar solicitudes DNS y responder con registros falsificados antes que el servidor DNS legítimo, asociando un dominio específico con una dirección IP controlada por el atacante y redirigiendo al usuario hacia un servicio web diferente al esperado.

---

## ⚙️ Requisitos

- Python 3.x
- Scapy (`pip install scapy`)
- Permisos root

---

## 🚀 Uso

```bash
sudo python3 dns.py
```

### Parámetros

| Parámetro | Descripción | Obligatorio |
|-----------|-------------|:-----------:|
| `iface` | Interfaz de red del atacante (ej. `eth0`) | ✅ |
| `SUBNET` | Red objetivo para detectar hosts activos (ej. `10.6.82.0/26`) | ✅ |
| `FAKE_PAGE_DIR` | Directorio donde se almacena la página web falsa | ✅ |
| `TARGET_DOMAIN` | Dominio que será falsificado (ej. `itla.edu.do`) | ✅ |

---

## 🔄 Flujo de Ejecución

```
1. El script detecta automáticamente la red local: IP del atacante, gateway y hosts activos
2. Se configura un servidor web falso en el equipo del atacante y se habilita IP Forwarding
3. Se realiza ARP Poisoning: MAC del atacante asociada a IP del gateway (y viceversa)
4. El script monitorea las consultas DNS enviadas por la víctima al servidor legítimo
5. Al detectar una consulta para el dominio objetivo, responde con la IP falsa del atacante
6. La víctima almacena la respuesta falsificada y es redirigida hacia la página web falsa
7. Al detener el ataque (Ctrl+C), se restauran las tablas ARP y se deshabilita IP Forwarding
```

---

## 🌐 Documentación de la Red

### Topología

| Dispositivo | Rol | Interfaz |
|-------------|-----|----------|
| Atacante (Kali Linux) | Máquina atacante | e0 |
| Switch (verde) | Switch de acceso | e0/1, e0/0 |
| Switch Secundario (rojo) | Switch de distribución | e0/0, e0/2 |
| Switch Principal (azul) | Switch core | e0/0, e0/1, e0/2 |
| Víctima | Host objetivo | e0 |
| Router Central | Gateway / DHCP | e0/0 |

### Direccionamiento

| Red | Máscara | Gateway | Rango Usable |
|-----|---------|---------|--------------|
| 10.6.82.0 | 255.255.255.0 | 10.6.82.1 | 10.6.82.2 – 10.6.82.254 |

---

## 🛡️ Contramedidas

| Medida | Comando / Acción | Efecto |
|--------|-----------------|--------|
| ARP Inspection | `ip arp inspection vlan x` | Valida los paquetes ARP recibidos y bloquea respuestas ARP falsificadas |

---

## ⚠️ Aviso Legal

> Este proyecto es exclusivamente con fines **educativos** en un entorno controlado de laboratorio. El uso de estas técnicas fuera de entornos autorizados es ilegal y éticamente incorrecto.
