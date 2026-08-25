# 🔍 LYRA - Herramienta OSINT (versión offline)

**LYRA** es una herramienta OSINT ligera diseñada para consultar información pública de **teléfonos**, **emails**, **dominios** y **usernames** en más de 280 plataformas, utilizando únicamente scraping y APIs gratuitas sin autenticación.

⚠️ **Aviso**: Esta versión es un prototipo funcional. No incluye todas las características prometidas en versiones anteriores. Está en desarrollo activo.

---

## 📌 Índice

- [¿Qué hace LYRA?](#qué-hace-lyra)
- [Características clave](#características-clave)
- [Instalación](#instalación)
- [Uso](#uso)
- [Configuración](#configuración)
- [Ética y legalidad](#ética-y-legalidad)
- [Licencia](#licencia)

---

## 🔍 ¿Qué hace LYRA?

LYRA automatiza la búsqueda de información pública disponible en internet. Actualmente incluye:

- **Teléfonos**: validación internacional, país, operador, ubicación, tipo de línea, coordenadas aproximadas y reportes de spam (SpamCalls).
- **Emails**: verificación de servidores MX, validación SMTP, detección de dominio desechable y análisis de seguridad (SPF, DKIM, DMARC).
- **Dominios**: consulta WHOIS, registros DNS (A, MX, NS) y certificado SSL.
- **Usernames**: escaneo masivo en más de 280 plataformas (redes sociales, foros, gaming, música, comercio, etc.)

**No incluye** (en esta versión): análisis de IP, scraping de LinkedIn/GitHub/Pastebin, verificación de WhatsApp/Telegram, integración con Maigret/Sherlock, ni análisis de riesgo VoIP/fraude.

---

## ⚙️ Características clave

### 📱 Módulo Teléfono
- Validación y formateo con `phonenumbers`.
- Geolocalización aproximada por país (coordenadas).
- Consulta de reportes de spam en `spamcalls.net`.
- Enlaces rápidos a Google Maps.

### 📧 Módulo Email
- Verificación de servidores MX.
- Validación SMTP (comprobación de existencia).
- Detección de dominio desechable.
- Análisis de seguridad: SPF, DKIM, DMARC.

### 🌐 Módulo Dominio
- WHOIS completo (registrador, fechas de creación/expiración, name servers).
- Registros DNS (A, MX, NS).
- Certificado SSL (validez, emisor, expiración).

### 👤 Módulo Username Masivo
- Escaneo en **~280 plataformas** (lista real, sin duplicados contados).
- Clasificación aproximada por categorías.
- Progreso en tiempo real.
- Filtrado de falsos positivos (páginas de error 404, "not found").
- Exportación de resultados en formato de lista.

---

## 🛠️ Tecnología y arquitectura

- **Lenguaje**: Python 3.8+
- **Librerías principales**:
  - `requests` – peticiones HTTP.
  - `phonenumbers` – validación de números.
  - `whois` – consulta WHOIS.
  - `dnspython` – resolución DNS.
  - `smtplib`, `ssl` – verificación SMTP y SSL.
- **APIs externas**:
  - `spamcalls.net` – reportes de spam telefónico.
  - `ipwho.is` – geolocalización de IP (no implementada en este código).
- **Scraping**:
  - Lista de plataformas para username (estática).

---

## 📥 Instalación

### Requisitos comunes
- Python 3.8 o superior.
- Git (opcional, para clonar).
- Conexión a Internet.

### 🔧 En Termux (Android)
```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python lyra.py
