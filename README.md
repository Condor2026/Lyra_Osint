# LYRA - Herramienta OSINT para investigadores

[![Version](https://img.shields.io/badge/version-1.0-red)](https://github.com/Condor2026/Lyra_Osint)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green)](https://python.org)
[![OSINT](https://img.shields.io/badge/OSINT-Pasivo%20%7C%20Analítico-blueviolet)](https://es.wikipedia.org/wiki/OSINT)
[![Termux](https://img.shields.io/badge/Termux-Compatible-orange)](https://termux.com)
[![Linux](https://img.shields.io/badge/Linux-Compatible-lightgrey)](https://linux.org)

**LYRA** es una herramienta OSINT pasiva y analítica diseñada para **consultar información pública de teléfonos, emails, direcciones IP y usernames en más de 300 plataformas**, con integración opcional para análisis avanzado de riesgo (VoIP/fraude) y herramientas profesionales como Maigret o Sherlock.  
Nace con una filosofía clara: *“Un gran poder conlleva una gran responsabilidad”*. Por eso su diseño prioriza la transparencia, la ética y el respeto a la privacidad.

---

## 📌 Índice

- [¿Qué hace LYRA?](#qué-hace-lyra)
- [Características clave](#características-clave)
- [Tecnología y arquitectura](#tecnología-y-arquitectura)
- [Instalación y uso](#instalación-y-uso)
- [Modo terminal (10 comandos)](#modo-terminal-10-comandos)
- [Configuración opcional](#configuración-opcional)
- [Ética, legalidad y protección de datos](#ética-legalidad-y-protección-de-datos)
- [Contribuciones y futuro](#contribuciones-y-futuro)
- [Licencia](#licencia)

---

## 🔍 ¿Qué hace LYRA?

LYRA automatiza la búsqueda de información pública disponible en internet, permitiendo a investigadores, periodistas y fuerzas de seguridad obtener datos relevantes sin necesidad de realizar consultas manuales repetitivas. La herramienta:

- **Consulta información de teléfonos**: país, operador, tipo de línea, geolocalización aproximada, reportes de spam, scraping de Truecaller y búsqueda en Telegram.
- **Analiza emails**: verifica si el dominio es desechable, consulta filtraciones en Have I Been Pwned y obtiene el perfil de Gravatar.
- **Geolocaliza IPs**: muestra país, ciudad, ISP y enlace a Google Maps.
- **Busca usernames en más de 300 plataformas**: redes sociales, foros, gaming, música, dating, crypto, etc., clasificados por categorías.
- **Ofrece herramientas de defensa**: enlace a SpamBlocker para bloquear llamadas spam.
- **Integra herramientas profesionales**: ejecuta Maigret (3000+ sitios) y Sherlock (300+ sitios) directamente desde LYRA.
- **Incluye utilidades complementarias**: búsqueda inversa de imágenes, escaneo de puertos y WHOIS de dominio mejorado con registros DNS.

---

## ⚙️ Características clave

### 📱 Módulo Teléfono
- Validación y formateo con `phonenumbers`.
- Geolocalización aproximada mediante Nominatim (OpenStreetMap) con enlace a Google Maps.
- Análisis de riesgo VoIP/fraude (opcional) a través de IPQualityScore.
- Consulta de reportes de spam en `spamcalls.net`.
- Scraping de Truecaller para obtener nombre público si está registrado.
- Búsqueda en Telegram por username o número.
- Enlaces rápidos a Tellows, SpamCalls, Google y Facebook.

### 📧 Módulo Email
- Detección de dominio desechable con lista actualizada desde GitHub.
- Consulta de filtraciones en Have I Been Pwned (con manejo de error 401).
- Obtención de perfil Gravatar si existe.
- Enlaces de búsqueda a Google, Facebook y Twitter.

### 🌐 Módulo IP
- Geolocalización con `ipwho.is`.
- Enlace directo al mapa de Google Maps.

### 👤 Módulo Username Masivo
- Más de 300 plataformas (redes sociales, foros, desarrollo, gaming, música, video, dating, compras, crypto, perfiles, seguridad, viajes, etc.).
- Clasificación automática por categorías.
- Progreso en tiempo real durante el escaneo.
- Filtrado de falsos positivos (páginas de error).

### 🛡️ Módulo Defensa
- **Spam Blocker**: proporciona el enlace para clonar e instalar la herramienta de bloqueo de llamadas spam de GitHub.

### 🔬 Módulo Herramientas Profesionales
- **Maigret**: instalación automática y ejecución con generación de reporte HTML (3000+ sitios).
- **Sherlock**: clonado automático, instalación de dependencias y ejecución (300+ sitios).
- **Enlaces a frameworks OSINT**: SpiderFoot, Recon-ng, Maltego.

### 🧩 Utilidades Complementarias
- **Búsqueda inversa de imágenes**: genera enlace a Google Images.
- **Escaneo de puertos**: detecta puertos abiertos comunes (21, 22, 23, 25, 80, 443, 8080, 3306, 3389).
- **WHOIS mejorado**: consulta whois + registros A (DNS) con `dnspython`.

---

## 🛠️ Tecnología y arquitectura

- **Lenguaje**: Python 3.8+
- **Librerías principales**:
  - `requests` – peticiones HTTP.
  - `phonenumbers` – validación y formateo de números internacionales.
  - `whois` – consulta WHOIS de dominios.
  - `dnspython` – resolución de registros DNS.
  - `socket` – escaneo de puertos.
  - `hashlib` – cálculo de hash para Gravatar.
- **APIs externas**:
  - `ipwho.is` – geolocalización de IP.
  - `spamcalls.net` – reportes de spam telefónico.
  - `haveibeenpwned.com` – filtraciones de email.
  - `ipqualityscore.com` – análisis VoIP/fraude (opcional, requiere clave).
- **Scraping**:
  - Truecaller (búsqueda pública).
  - Plataformas de username (300+).
- **Arquitectura modular**: cada opción del menú se implementa como una función independiente, facilitando el mantenimiento y la extensión.

---

## 📥 Instalación y uso

### Requisitos comunes
- Python 3.8 o superior.
- `git` (para clonar el repositorio).
- Conexión a Internet.

### 🔧 Instalación paso a paso

#### 📱 Opción 1: En Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests phonenumbers whois dnspython
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python Lyra_Osint.py
