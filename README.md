
# 🔍 LYRA PRO - OSINT Ético y Funcional

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![OSINT](https://img.shields.io/badge/OSINT-Open%20Source-orange)

**LYRA PRO** es una herramienta OSINT (Open Source Intelligence) diseñada para investigadores, periodistas y profesionales de la seguridad. Permite consultar información pública de **teléfonos**, **emails**, **dominios** y **usernames** de forma ética y legal, utilizando únicamente scraping y APIs gratuitas.

---

## 📌 Índice

- [Características principales](#-características-principales)
- [Instalación](#-instalación)
- [Uso y menú](#-uso-y-menú)
- [Explicación de módulos](#-explicación-de-módulos)
- [Configuración](#-configuración)
- [Limitaciones conocidas](#-limitaciones-conocidas)
- [Ética y legalidad](#-ética-y-legalidad)
- [Contribuciones](#-contribuciones)
- [Licencia](#-licencia)

---

## ⚙️ Características principales

LYRA PRO ofrece **4 módulos de análisis** y **3 motores de búsqueda de usernames**, todo en un solo menú interactivo.

| Módulo | Funciones | Estado |
|--------|-----------|--------|
| **📱 Teléfono** | Validación internacional, país, operador, ubicación, tipo de línea, coordenadas GPS, reportes de spam (SpamCalls) | ✅ Funcional |
| **📧 Email** | Servidores MX, verificación SMTP (básica), detección de dominio desechable, SPF/DKIM/DMARC | ✅ Funcional |
| **🌐 Dominio** | WHOIS (registrador, fechas), registros DNS (A, MX, NS), certificado SSL | ✅ Funcional |
| **👤 Username (LYRA Engine)** | ~120 sitios depurados (redes sociales, foros, gaming, comercio, etc.) | ✅ Siempre disponible |
| **⚡ Username (Maigret)** | 3000+ sitios (instalación automática desde opción 8) | ✅ Opcional |
| **⚡ Username (Sherlock)** | 479 sitios (instalación automática desde opción 8) | ✅ Opcional |
| **🤖 Análisis Automático** | Detecta automáticamente si el target es email, teléfono, dominio o username | ✅ Funcional |
| **🔧 Instalación de herramientas** | Instala Maigret y Sherlock directamente desde LYRA | ✅ Funcional |

---

## 📥 Instalación

### Requisitos previos
- Python 3.8 o superior.
- Git (opcional, para clonar el repositorio).
- Conexión a Internet (para las consultas y descarga de herramientas).

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

## ⌨️ Uso y menú

Al ejecutar LYRA, se muestra un banner y un menú con las siguientes opciones:

```
[1] 📱 Análisis de Teléfono
[2] 📧 Análisis de Email
[3] 🌐 Análisis de Dominio
[4] 👤 Username Tracking (LYRA - ~120 sitios)
[5] ⚡ Username Tracking (Maigret - 3000+ sitios)
[6] ⚡ Username Tracking (Sherlock - 479 sitios)
[7] 🤖 Análisis Automático
[8] 🔧 Instalar Herramientas (Maigret/Sherlock)
[0] 🚪 Salir
```

### 🔹 Explicación de cada opción

1. **Análisis de Teléfono**  
   - Introduce un número con código de país (ej. `+34123456789`).  
   - LYRA te devuelve: país, operador, ubicación, tipo de línea, coordenadas aproximadas y si tiene reportes de spam.

2. **Análisis de Email**  
   - Introduce un email (ej. `usuario@dominio.com`).  
   - LYRA comprueba: servidores MX, si el dominio es desechable, y el estado de SPF/DKIM/DMARC.  
   - *(La verificación SMTP puede fallar si el servidor bloquea IPs dinámicas; no es un error de LYRA).*

3. **Análisis de Dominio**  
   - Introduce un dominio (ej. `ejemplo.com`).  
   - LYRA consulta: WHOIS (registrador, fechas de creación/expiración), registros DNS (A, MX, NS) y certificado SSL.

4. **Username Tracking (LYRA Engine)**  
   - Introduce un nombre de usuario.  
   - LYRA escanea su lista de ~120 sitios depurados y te muestra aquellos donde el perfil existe.  
   - Es normal obtener entre 10 y 40 resultados de calidad.

5. **Username Tracking (Maigret)**  
   - Requiere Maigret instalado (opción 8).  
   - Escanea más de 3000 sitios en busca del username.  
   - Puede tardar varios minutos. Los resultados se guardan en caché.

6. **Username Tracking (Sherlock)**  
   - Requiere Sherlock instalado (opción 8).  
   - Escanea 479 sitios. También puede tardar varios minutos.

7. **Análisis Automático**  
   - Introduce cualquier target (email, teléfono, dominio o @username).  
   - LYRA detecta automáticamente el tipo y ejecuta el módulo correspondiente.

8. **Instalar Herramientas**  
   - Menú para instalar Maigret y Sherlock directamente desde LYRA.  
   - Maigret se instala clonando el repositorio y creando un entorno virtual.  
   - Sherlock se instala mediante `pip`.

---

## 🛠️ Tecnología y arquitectura

LYRA está construida en Python y utiliza las siguientes librerías y fuentes:

| Librería/API | Uso |
|--------------|-----|
| `requests` | Peticiones HTTP a APIs y scraping |
| `phonenumbers` | Validación y formateo de números internacionales |
| `whois` | Consulta WHOIS de dominios |
| `dnspython` | Resolución de registros DNS |
| `smtplib`, `ssl` | Verificación SMTP y certificados SSL |
| `spamcalls.net` | API gratuita para reportes de spam telefónico |
| `Maigret` | Herramienta externa (3000+ sitios) |
| `Sherlock` | Herramienta externa (479 sitios) |
| SQLite | Caché local para agilizar consultas repetidas |

---

## ⚙️ Configuración

LYRA genera un archivo `config.yaml` en la primera ejecución. Puedes editarlo para ajustar:

```yaml
general:
  timeout: 15                # Tiempo de espera para peticiones HTTP
  max_retries: 3             # Reintentos en caso de fallo
  verbose: false             # Modo detallado
  save_results: true         # Guardar resultados en archivos
  output_dir: 'output'       # Carpeta de salida
  cache_enabled: true        # Habilitar caché
  cache_ttl: 86400           # Tiempo de vida del caché (segundos)
  max_threads: 20            # Hilos para escaneo de usernames
```

**No requiere API keys para las funciones básicas.**

---

## 🚫 Limitaciones conocidas

LYRA es una herramienta en desarrollo activo. Estas son sus limitaciones actuales:

- ❌ **No tiene análisis de IP** (geolocalización, reputación, etc.).
- ❌ **No hace scraping de LinkedIn, GitHub ni Pastebin**.
- ❌ **No verifica WhatsApp/Telegram automáticamente** (solo muestra enlaces manuales).
- ❌ **Maigret y Sherlock son opcionales** (requieren instalación desde la opción 8).
- ✅ **El motor LYRA es estable** y escanea ~120 sitios depurados sin API.

---

## 🛡️ Ética y legalidad

LYRA es una herramienta de código abierto diseñada exclusivamente para **fines educativos y de investigación legítima**. Su uso debe cumplir con:

- Leyes de protección de datos (GDPR, LOPDGDD, etc.).
- Consentimiento explícito del objetivo en investigaciones privadas.
- Fines legales: seguridad, periodismo, verificación de identidad, búsqueda de personas desaparecidas (con autorización).

**Prohibido**:
- Acoso, doxing o vigilancia no consensuada.
- Violación de privacidad.
- Actividades ilegales de cualquier tipo.

**El autor no se responsabiliza del mal uso de esta herramienta.**

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Áreas de mejora:

- Añadir más plataformas a la lista de LYRA (sin duplicados).
- Implementar análisis de IP con APIs gratuitas (ip-api.com, ipwho.is).
- Integrar scraping de LinkedIn/GitHub (respetando robots.txt).
- Mejorar la validación SMTP con reintentos y múltiples servidores MX.
- Añadir exportación de resultados en HTML, CSV o PDF.

Si quieres contribuir, abre un issue o un pull request en [GitHub](https://github.com/Condor2026/Lyra_Osint).

---

## 📄 Licencia

MIT License

Copyright (c) 2024 Condor2026

Se concede permiso, de forma gratuita, a cualquier persona que obtenga una copia de este software y de los archivos de documentación asociados, para utilizar el Software sin restricción, incluyendo sin limitación los derechos de uso, copia, modificación, fusión, publicación, distribución, sublicencia y/o venta de copias del Software, y para permitir a las personas a las que se les proporcione el Software a hacerlo, sujeto a las siguientes condiciones:

El aviso de copyright anterior y este aviso de permiso se incluirán en todas las copias o partes sustanciales del Software.

EL SOFTWARE SE PROPORCIONA "TAL CUAL", SIN GARANTÍA DE NINGÚN TIPO, EXPRESA O IMPLÍCITA, INCLUYENDO PERO NO LIMITADO A GARANTÍAS DE COMERCIABILIDAD, IDONEIDAD PARA UN PROPÓSITO PARTICULAR Y NO INFRACCIÓN. EN NINGÚN CASO LOS AUTORES O TITULARES DEL COPYRIGHT SERÁN RESPONSABLES DE NINGUNA RECLAMACIÓN, DAÑO U OTRA RESPONSABILIDAD, YA SEA EN UNA ACCIÓN DE CONTRATO, AGRAVIO O DE OTRO TIPO, QUE SURJA DE, FUERA DE O EN RELACIÓN CON EL SOFTWARE O EL USO U OTRO TIPO DE ACCIONES EN EL SOFTWARE.

---

⭐ **Apoya el proyecto**  
Si LYRA te ha sido útil, dale una estrella ⭐ en GitHub, reporta bugs o comparte con otros investigadores.

🔗 [GitHub del proyecto](https://github.com/Condor2026/Lyra_Osint)

---

🦅 **Condor2026 - Threat Security**
```
