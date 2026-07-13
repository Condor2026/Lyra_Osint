# 🔍 LYRA - Herramienta OSINT para investigadores

[![Version](https://img.shields.io/badge/version-2.0-red)](https://github.com/Condor2026/Lyra_Osint)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green)](https://python.org)
[![OSINT](https://img.shields.io/badge/OSINT-Pasivo%20%7C%20Analítico-blueviolet)](https://es.wikipedia.org/wiki/OSINT)
[![Termux](https://img.shields.io/badge/Termux-Compatible-orange)](https://termux.com)
[![Linux](https://img.shields.io/badge/Linux-Compatible-lightgrey)](https://linux.org)

**LYRA** es una herramienta OSINT pasiva y analítica diseñada para **consultar información pública de teléfonos, emails, direcciones IP y usernames en más de 300 plataformas**, con integración opcional para análisis avanzado de riesgo (VoIP/fraude) y herramientas profesionales como Maigret o Sherlock.  
Nace con una filosofía clara: *"Un gran poder conlleva una gran responsabilidad"*. Por eso su diseño prioriza la transparencia, la ética y el respeto a la privacidad.

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
- **Analiza emails**: verifica si el dominio es desechable, consulta filtraciones en Have I Been Pwned, reputación, LinkedIn, GitHub, Pastebin y obtiene el perfil de Gravatar.
- **Geolocaliza IPs**: muestra país, ciudad, ISP y enlace a Google Maps.
- **Analiza dominios**: WHOIS, registros DNS, SSL, VirusTotal, URLScan, subdominios y seguridad.
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
- Verificación de presencia en WhatsApp.
- Enlaces rápidos a Tellows, SpamCalls, Google y Facebook.

### 📧 Módulo Email
- Detección de dominio desechable con lista actualizada.
- Verificación de servidores MX.
- Validación SMTP.
- Consulta de filtraciones en Have I Been Pwned.
- Reputación del email con EmailRep.io.
- Búsqueda de perfil en LinkedIn.
- Búsqueda de commits en GitHub.
- Búsqueda en Pastebin.
- Análisis de riesgo de spoofing (SPF, DKIM, DMARC).
- Score de confianza.

### 🌐 Módulo IP
- Geolocalización con `ipwho.is`.
- Enlace directo al mapa de Google Maps.

### 🌐 Módulo Dominio
- WHOIS completo (registrador, fechas, name servers).
- Registros DNS (A, AAAA, MX, NS, TXT).
- Certificado SSL.
- VirusTotal (requiere API key).
- URLScan.io.
- Wayback Machine.
- Enumeración de subdominios.
- Tecnologías detectadas.
- Headers de seguridad.
- Score de riesgo.

### 👤 Módulo Username Masivo
- Más de 300 plataformas (redes sociales, foros, desarrollo, gaming, música, video, dating, compras, crypto, perfiles, seguridad, viajes, etc.).
- Clasificación automática por categorías.
- Progreso en tiempo real durante el escaneo.
- Filtrado de falsos positivos (páginas de error).
- Exportación de resultados.

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
  - `smtplib` – verificación SMTP.
  - `ssl` – información de certificados SSL.
- **APIs externas**:
  - `ipwho.is` – geolocalización de IP.
  - `spamcalls.net` – reportes de spam telefónico.
  - `haveibeenpwned.com` – filtraciones de email.
  - `ipqualityscore.com` – análisis VoIP/fraude (opcional, requiere clave).
  - `emailrep.io` – reputación de email.
  - `virustotal.com` – análisis de dominios (requiere API key).
  - `urlscan.io` – análisis de dominios.
- **Scraping**:
  - Truecaller (búsqueda pública).
  - Plataformas de username (300+).
  - LinkedIn, GitHub, Pastebin.

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
pip install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python lyra.py
```

#### 💻 Opción 2: En Linux (Debian/Ubuntu/Kali)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
pip3 install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python3 lyra.py
```

#### 🪟 Opción 3: En Windows

```bash
# Instalar Python desde python.org
# Abrir CMD o PowerShell
pip install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python lyra.py
```

---

## ⌨️ Modo terminal (10 comandos)

LYRA cuenta con un menú interactivo con las siguientes opciones:

```
╔══════════════════════════════════════════════════════════╗
║                    M E N Ú   P R I N C I P A L            ║
╚══════════════════════════════════════════════════════════╝

[1] 📧 Análisis de Email
   Completo con LinkedIn, GitHub, Pastebin

[2] 📱 Análisis de Teléfono
   Geo, riesgo, spam, WhatsApp, Truecaller

[3] 🌐 Análisis de Dominio
   WHOIS, DNS, SSL, VirusTotal, subdominios

[4] 👤 Username Tracking
   Buscar en 300+ plataformas

[5] 🤖 Análisis Automático
   Detecta email, teléfono, dominio o username

[6] 📊 Ver Resultados
   Historial de la sesión

[7] ⚙️ Configuración
   APIs y opciones

[0] 🚪 Salir
   Salir de LYRA
```

---

## ⚙️ Configuración opcional

LYRA genera automáticamente un archivo `config.yaml` en la primera ejecución. Puedes editarlo para añadir tus API keys:

```yaml
apis:
  ipqualityscore: 'tu_api_key'    # Para análisis VoIP/fraude
  hibp: 'tu_api_key'              # Have I Been Pwned
  virustotal: 'tu_api_key'        # Análisis de dominios
  emailrep: 'https://emailrep.io/'
  urlscan: ''                     # URLScan.io

general:
  timeout: 15
  max_retries: 3
  verbose: false
  save_results: true
  output_dir: 'output'
  cache_enabled: true
  cache_ttl: 86400
  max_threads: 20
```

---

## 🛡️ Ética, legalidad y protección de datos

LYRA es una herramienta de **código abierto** diseñada para fines **educativos y de investigación legítima**. Su uso debe cumplir con:

- **Leyes de protección de datos** (GDPR, LOPDGDD, etc.).
- **Consentimiento explícito** del objetivo en investigaciones privadas.
- **Fines exclusivamente legales**: seguridad, periodismo, verificación de identidad, búsqueda de personas desaparecidas.
- **Prohibición expresa** de:
  - Acoso, doxing o vigilancia no consensuada.
  - Violación de privacidad.
  - Actividades ilegales de cualquier tipo.

**El autor no se responsabiliza del mal uso de esta herramienta.**

---

## 🤝 Contribuciones y futuro

LYRA está en constante evolución. Las contribuciones son bienvenidas a través de:

- **Issues**: reporte de bugs o sugerencias.
- **Pull Requests**: nuevas funcionalidades o mejoras.
- **Documentación**: traducciones o ejemplos de uso.

### 📋 Hoja de ruta

- [x] Módulo de email completo
- [x] Módulo de teléfono completo
- [x] Módulo de dominio completo
- [x] Username tracking (300+ plataformas)
- [x] Integración con Maigret y Sherlock
- [x] Exportación de resultados (JSON, HTML)
- [x] Sistema de caché
- [ ] Interfaz web (en desarrollo)
- [ ] API REST (en desarrollo)
- [ ] Plugin system (en desarrollo)

---

## 📄 Licencia

LYRA se distribuye bajo la licencia **MIT**. Esto permite su uso, modificación y distribución siempre que se mantenga el aviso de copyright y la licencia original.

```
MIT License

Copyright (c) 2024 Condor2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## ⭐ Apoya el proyecto

Si LYRA te ha sido útil, considera:

- 🌟 Darle una estrella en GitHub.
- 🐛 Reportar bugs o sugerir mejoras.
- 📚 Compartir el proyecto con otros investigadores.
- 💰 Contribuir con donaciones (opcional).

---

**LYRA** - *"Un gran poder conlleva una gran responsabilidad"*

🔗 [GitHub](https://github.com/Condor2026/Lyra_Osint) | [Reportar issue](https://github.com/Condor2026/Lyra_Osint/issues)
```

---

## 📋 Resumen del README

| Sección | Contenido |
|---------|-----------|
| **Badges** | Versión, licencia, Python, OSINT, Termux, Linux |
| **Descripción** | Qué es LYRA y su filosofía |
| **Características** | Todos los módulos detallados |
| **Tecnología** | Librerías, APIs y arquitectura |
| **Instalación** | Termux, Linux, Windows |
| **Comandos** | Menú completo de 10 opciones |
| **Configuración** | Archivo config.yaml |
| **Ética** | Aviso legal y uso responsable |
| **Contribuciones** | Cómo colaborar |
| **Licencia** | MIT |

