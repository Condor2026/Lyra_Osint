## 📋 Análisis real del código LYRA

He revisado el código que has pegado. **Esto es lo que realmente hace** (sin exageraciones):

---

### 🔍 Módulos que realmente existen

| Módulo | Funciones reales | Lo que NO hace |
|--------|------------------|----------------|
| **EmailAnalyzer** | ✔ MX (servidores de correo)<br>✔ SMTP (verificación básica)<br>✔ Dominio desechable<br>✔ SPF/DKIM/DMARC | ✘ Reputación (EmailRep)<br>✘ Filtraciones (HIBP)<br>✘ Pastebins (psbdmp)<br>✘ LinkedIn/GitHub scraping |
| **PhoneAnalyzer** | ✔ Validación internacional<br>✔ País, operador, ubicación, tipo<br>✔ Coordenadas aproximadas (por país)<br>✔ SpamCalls.net (reportes) | ✘ WhatsApp/Telegram real<br>✘ Truecaller scraping<br>✘ Análisis VoIP/fraude |
| **DomainAnalyzer** | ✔ WHOIS (registrador, fechas)<br>✔ DNS (A, MX, NS)<br>✔ SSL (validez, emisor, expiración) | ✘ VirusTotal<br>✘ URLScan<br>✘ Subdominios<br>✘ Tecnologías |
| **UsernameTracker** | ✔ Escanea **~300 plataformas** (con duplicados)<br>✔ Verifica existencia por código HTTP<br>✔ Filtra páginas de error comunes | ✘ 401 únicas (hay duplicados)<br>✘ Clasificación por categorías real |

---

### 📊 Detalle de plataformas en UsernameTracker

El código contiene una lista de **~350 entradas**, pero muchas están repetidas (WeChat, Weibo, Renren, etc.). Tras eliminar duplicados, el número real es **~280-300 únicas**.

**Categorías reales** (las que aparecen en el código):
- Redes sociales (Twitter, Instagram, Facebook, etc.)
- Blogs (Medium, WordPress, Blogger)
- Código (GitHub, GitLab, CodePen)
- Foros (StackOverflow, Reddit, Quora)
- Video (Twitch, Vimeo, Dailymotion)
- Música (SoundCloud, Spotify, Bandcamp)
- Juegos (Steam, PlayStation, Roblox)
- Crypto (OpenSea, Binance, Etherscan)
- Comercio (Amazon, eBay, AliExpress)
- Profesionales (Upwork, Fiverr, LinkedIn)
- Dating (Tinder, Bumble, OKCupid)
- Fitness (Strava, Fitbit)
- Viajes (Airbnb, Booking)
- Educativas (Coursera, Udemy)
- Científicas (ResearchGate, Academia.edu)
- Latinoamérica/Europa (Taringa, ForoCoches, Meneame)
- Asia (Weibo, QQ, Zhihu)
- Seguridad (HackTheBox, TryHackMe)

---

### 🚫 Lo que NO hace este código (aunque el README viejo lo prometía)

- ❌ No tiene análisis de IP
- ❌ No integra Maigret ni Sherlock
- ❌ No tiene Web scraping de Truecaller
- ❌ No verifica WhatsApp/Telegram real (solo enlaces en la salida)
- ❌ No usa IPQualityScore (riesgo VoIP/fraude)
- ❌ No usa EmailRep, HIBP, psbdmp
- ❌ No tiene módulo de defensa
- ❌ No tiene utilidades de imagen, puertos, etc.

---

## 📄 README.md REAL (basado en el código actual)

```markdown
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
```

### 💻 En Linux (Debian/Ubuntu/Kali)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
pip3 install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python3 lyra.py
```

### 🪟 En Windows
```powershell
pip install requests phonenumbers whois dnspython pyyaml
git clone https://github.com/Condor2026/Lyra_Osint.git
cd Lyra_Osint
python lyra.py
```

---

## ⌨️ Uso

El menú principal ofrece las siguientes opciones:

```
╔══════════════════════════════════════════════════════════╗
║                    M E N Ú   P R I N C I P A L            ║
╚══════════════════════════════════════════════════════════╝

[1] 📱 Análisis de Teléfono
[2] 📧 Análisis de Email
[3] 🌐 Análisis de Dominio
[4] 👤 Username Tracking (280+ plataformas)
[5] 🤖 Análisis Automático
[0] 🚪 Salir
```

### 🔹 Análisis de Teléfono
- Introduce un número con código de país (ej. `+34123456789`).
- Obtendrás: país, operador, ubicación, tipo, coordenadas y reportes de spam.

### 🔹 Análisis de Email
- Introduce un email (ej. `usuario@dominio.com`).
- Obtendrás: servidores MX, validación SMTP, si es desechable y estado de SPF/DKIM/DMARC.

### 🔹 Análisis de Dominio
- Introduce un dominio (ej. `ejemplo.com`).
- Obtendrás: WHOIS, registros DNS y estado del certificado SSL.

### 🔹 Username Tracking
- Introduce un nombre de usuario.
- LYRA escaneará la lista de plataformas y mostrará aquellas donde el usuario existe.

---

## ⚙️ Configuración (opcional)

LYRA genera un archivo `config.yaml` en la primera ejecución. Puedes editarlo para personalizar opciones:

```yaml
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

No requiere API keys para las funciones básicas.

---

## 🛡️ Ética y legalidad

LYRA es una herramienta de código abierto diseñada para fines educativos y de investigación legítima. Su uso debe cumplir con:

- Leyes de protección de datos (GDPR, LOPDGDD, etc.).
- Consentimiento explícito del objetivo en investigaciones privadas.
- Fines exclusivamente legales: seguridad, periodismo, verificación de identidad.

**Prohibido**:
- Acoso, doxing o vigilancia no consensuada.
- Violación de privacidad.
- Actividades ilegales.

El autor no se responsabiliza del mal uso.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Áreas de mejora:
- Añadir más plataformas a la lista de username (sin duplicados).
- Implementar análisis de IP.
- Integrar scraping de LinkedIn/GitHub.
- Añadir soporte para APIs de riesgo (IPQS, EmailRep, etc.).

---

## 📄 Licencia

MIT License

Copyright (c) 2024 Condor2026

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia de este software y de los archivos de documentación asociados, para utilizar el Software sin restricción, incluyendo sin limitación los derechos de uso, copia, modificación, fusión, publicación, distribución, sublicencia y/o venta de copias del Software, y para permitir a las personas a las que se les proporcione el Software a hacerlo, sujeto a las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las copias o partes sustanciales del Software.

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO PERO NO LIMITADO A GARANTÍAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN. EN NINGÚN CASO LOS AUTORES O TITULARES DEL COPYRIGHT SERÁN RESPONSABLES DE NINGUNA RECLAMACIÓN, DAÑO U OTRA RESPONSABILIDAD, YA SEA EN UNA ACCIÓN DE CONTRATO, AGRAVIO O DE OTRO TIPO, QUE SURJA DE, FUERA DE O EN RELACIÓN CON EL SOFTWARE O EL USO U OTRO TIPO DE ACCIONES EN EL SOFTWARE.

---

⭐ **Apoya el proyecto**  
Si LYRA te ha sido útil, dale una estrella en GitHub, reporta bugs o comparte con otros investigadores.

🔗 [GitHub del proyecto](https://github.com/Condor2026/Lyra_Osint)

---

🦅 **Condor2026 - Threat Security**
```
