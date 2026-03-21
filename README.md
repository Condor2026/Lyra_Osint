# LYRA - Herramienta OSINT para investigadores

**Versión 1.0 | Licencia MIT | Python 3 | Termux/Linux**

LYRA es una herramienta OSINT pasiva y analítica diseñada para facilitar investigaciones de fuentes abiertas. Permite consultar información pública sobre teléfonos, emails, direcciones IP y usernames en más de 300 plataformas, con integración opcional para análisis avanzado de riesgo (VoIP/fraude) y herramientas profesionales como Maigret o Sherlock.

> ⚠️ **ADVERTENCIA LEGAL**  
> Esta herramienta es exclusivamente para fines educativos y de investigación legítima.  
> No debe utilizarse para acosar, doxear, realizar actividades ilegales o violar la privacidad de las personas.  
> El autor no se responsabiliza del mal uso. El usuario es el único responsable de cumplir con las leyes de su país.

---

## 📋 Índice

- [Características clave](#-características-clave)
- [Instalación](#-instalación)
- [Uso básico](#-uso-básico)
- [Configuración opcional](#-configuración-opcional)
- [Tecnología y arquitectura](#-tecnología-y-arquitectura)
- [Ética, legalidad y protección de datos](#-ética-legalidad-y-protección-de-datos)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)

---

## ✨ Características clave

### 📱 Teléfono
- País, operador, tipo de línea (fijo/móvil).
- Geolocalización aproximada con OpenStreetMap y enlace a Google Maps.
- Análisis de riesgo VoIP/fraude mediante IPQualityScore (opcional).
- Consulta de reportes de spam en spamcalls.net.
- Scraping de Truecaller (nombre público si existe).
- Búsqueda en Telegram por username o número.
- Enlaces rápidos a Tellows, SpamCalls, Google y Facebook.

### 📧 Email
- Verificación de dominio desechable (lista actualizada desde GitHub).
- Consulta de filtraciones en Have I Been Pwned.
- Obtención de perfil de Gravatar.
- Enlaces de búsqueda en Google, Facebook y Twitter.

### 🌐 IP
- Geolocalización con país, ciudad e ISP.
- Enlace directo al mapa de Google Maps.

### 👤 Username masivo
- Búsqueda en más de 300 plataformas (redes sociales, foros, gaming, música, dating, crypto, etc.).
- Clasificación por categorías.
- Progreso en tiempo real.

### 🛡️ Defensa
- Spam Blocker: enlace a la herramienta de bloqueo de llamadas spam.

### 🔬 Herramientas profesionales
- Ejecución automática de **Maigret** (3000+ sitios).
- Ejecución automática de **Sherlock** (300+ sitios).
- Enlaces a frameworks OSINT (SpiderFoot, Recon-ng, Maltego).

---

## 📦 Instalación

### En Termux (Android)
```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests phonenumbers whois dnspython
git clone https://github.com/tu-usuario/LYRA.git
cd LYRA
python lyra.py
