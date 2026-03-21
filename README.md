# LYRA - Herramienta OSINT para investigadores

LYRA es una herramienta de código abierto diseñada para facilitar investigaciones OSINT (Open Source Intelligence) de forma ética y legal. Permite consultar información pública sobre teléfonos, emails, direcciones IP y usernames en más de 300 plataformas, con integración opcional para bases de datos propias vía Telegram bot.

> ⚠️ **ADVERTENCIA LEGAL**  
> Esta herramienta es exclusivamente para fines educativos y de investigación legítima.  
> No debe utilizarse para acosar, doxear, realizar actividades ilegales o violar la privacidad de las personas.  
> El autor no se responsabiliza del mal uso. El usuario es el único responsable de cumplir con las leyes de su país.

---

## ✨ Características principales

- **📱 Teléfono**  
  - País, operador, tipo de línea.  
  - Geolocalización aproximada (OpenStreetMap).  
  - Análisis VoIP/riesgo (IPQualityScore – opcional).  
  - Reportes de spam (spamcalls.net).  
  - Scraping de Truecaller.  
  - Búsqueda en Telegram.  
  - Consulta a bot de dumps propio (configurable).  
  - Enlaces rápidos a Tellows, Google, Facebook.

- **📧 Email**  
  - Dominio desechable.  
  - Filtraciones en Have I Been Pwned.  
  - Perfil de Gravatar.

- **🌐 IP**  
  - Geolocalización con mapa.

- **👤 Username masivo**  
  - Más de 300 plataformas (redes sociales, foros, gaming, música, crypto, etc.) agrupadas por categorías.

- **🛡️ Anti‑spam**  
  - Spam Blocker (defensa, enlace a SpamBlocker de GitHub).

- **🔬 Herramientas profesionales**  
  - Instalación y ejecución de Maigret (3000+ sitios).  
  - Instalación y ejecución de Sherlock (300+ sitios).  
  - Enlaces a frameworks OSINT.

---

## 📦 Instalación en Termux / Linux

### 1. Dependencias básicas
```bash
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests phonenumbers whois dnspython
