#!/usr/bin/env python3
# ==========================================================
# LYRA PRO - OSINT COMPLETO (CON MAIGRET FUNCIONAL)
# TODAS LAS FUNCIONES - SIN ERRORES SQL - MAIGRET AUTOMÁTICO
# ==========================================================

import json
import requests
import time
import os
import re
import random
import sys
import sqlite3
import subprocess
import shutil
import venv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import socket
import dns.resolver
import smtplib
import whois
import ssl
import phonenumbers
from phonenumbers import carrier, geocoder

# ==========================================================
# COLORES
# ==========================================================
class Colors:
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
ORANGE = '\033[38;5;208m'
WHITE = '\033[97m'
CYAN = '\033[96m'
PURPLE = '\033[95m'
GRAY = '\033[90m'
BOLD = '\033[1m'
RESET = '\033[0m'

def header(t):
print(f"\n{Colors.CYAN}╔{'═'*50}╗{Colors.RESET}")
print(f"{Colors.CYAN}║{t.center(50)}║{Colors.RESET}")
print(f"{Colors.CYAN}╚{'═'*50}╝{Colors.RESET}")

# ==========================================================
# CACHE (CORREGIDO)
# ==========================================================
class Cache:
def __init__(self):
Path("cache").mkdir(exist_ok=True)
self.db = sqlite3.connect("cache/cache.db", check_same_thread=False)
self.db.execute('''CREATE TABLE IF NOT EXISTS cache (
key TEXT PRIMARY KEY,
value TEXT,
timestamp INTEGER,
ttl INTEGER
)''')
self.db.commit()

def get(self, key):
try:
r = self.db.execute('SELECT value, timestamp, ttl FROM cache WHERE key=?', (key,)).fetchone()
if r and time.time() - r[1] < r[2]:
return json.loads(r[0])
except:
pass
return None

def set(self, key, value, ttl=86400):
try:
self.db.execute('REPLACE INTO cache (key, value, timestamp, ttl) VALUES (?,?,?,?)',
(key, json.dumps(value), int(time.time()), ttl))
self.db.commit()
except:
pass

cache = Cache()

# ==========================================================
# DETECCIÓN DE TIPO
# ==========================================================
def detect_type(target: str) -> str:
target = target.strip()
if '@' in target and '.' in target.split('@')[1]:
return 'email'
if target.startswith('+') and len(target) >= 10 and target[1:].isdigit():
return 'phone'
if '.' in target and ' ' not in target and not target.startswith('@'):
return 'domain'
if target.startswith('@'):
return 'username'
return 'username'

# ==========================================================
# EMAIL ANALYZER
# ==========================================================
class EmailAnalyzer:
def __init__(self):
self.cache = cache

def analyze(self, email: str) -> Dict:
if '@' not in email:
return {'error': 'Email inválido'}
email = email.lower().strip()
domain = email.split('@')[1]
result = {'email': email, 'domain': domain, 'timestamp': datetime.now().isoformat(), 'data': {}}
result['data']['mx'] = self._mx(domain)
result['data']['smtp'] = self._smtp(email, domain)
result['data']['disposable'] = self._disposable(domain)
result['data']['spoofing'] = self._spoofing(domain)
return result

def _mx(self, domain: str) -> Dict:
key = f"mx_{domain}"
cached = cache.get(key)
if cached: return cached
r = {'has_mx': False, 'records': []}
try:
answers = dns.resolver.resolve(domain, 'MX')
r['has_mx'] = True
for mx in answers:
r['records'].append({'exchange': str(mx.exchange), 'preference': mx.preference})
r['records'] = sorted(r['records'], key=lambda x: x['preference'])
except: pass
cache.set(key, r, 3600)
return r

def _smtp(self, email: str, domain: str) -> Dict:
key = f"smtp_{email}"
cached = cache.get(key)
if cached: return cached
r = {'valid': False, 'message': 'No verificado'}
mx = self._mx(domain)
if not mx.get('records'):
r['message'] = 'No hay servidores MX'
return r
try:
with smtplib.SMTP(str(mx['records'][0]['exchange']), timeout=10) as smtp:
smtp.ehlo()
smtp.mail('test@example.com')
code, _ = smtp.rcpt(email)
if code in [250, 251]:
r['valid'] = True
r['message'] = 'Email válido'
elif code == 550:
r['valid'] = False
r['message'] = 'Email inválido'
except Exception as e:
r['message'] = f'Error: {str(e)[:50]}'
cache.set(key, r, 3600)
return r

def _disposable(self, domain: str) -> Dict:
key = f"disp_{domain}"
cached = cache.get(key)
if cached: return cached
dominios = {'mailinator.com','guerrillamail.com','tempmail.com','10minutemail.com',
'throwawayemail.com','spamgourmet.com','yopmail.com','getnada.com',
'fakeinbox.com','ghostmail.com','maildrop.cc'}
r = {'is_disposable': domain in dominios}
cache.set(key, r)
return r

def _spoofing(self, domain: str) -> Dict:
r = {'has_spf': False, 'has_dkim': False, 'has_dmarc': False}
try:
for txt in dns.resolver.resolve(domain, 'TXT'):
if 'v=spf1' in str(txt):
r['has_spf'] = True
except: pass
try:
dns.resolver.resolve(f'_domainkey.{domain}', 'TXT')
r['has_dkim'] = True
except: pass
try:
dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
r['has_dmarc'] = True
except: pass
return r

def format(self, results: Dict) -> str:
if 'error' in results:
return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"
out = []
data = results.get('data', {})
header("📧 ANÁLISIS DE EMAIL")
out.append(f"{Colors.CYAN}Email: {Colors.WHITE}{results['email']}")
out.append(f"{Colors.CYAN}Dominio: {Colors.WHITE}{results['domain']}")

mx = data.get('mx', {})
out.append(f"\n{Colors.CYAN}📌 SERVIDORES MX:")
if mx.get('records'):
for r in mx['records'][:3]:
out.append(f"{Colors.WHITE}  📤 {r['exchange']} (Prio: {r['preference']})")
else:
out.append(f"{Colors.YELLOW}  ⚠ No encontrados")

smtp = data.get('smtp', {})
out.append(f"\n{Colors.CYAN}📌 VERIFICACIÓN SMTP:")
if smtp.get('valid'):
out.append(f"{Colors.GREEN}  ✅ Válido")
else:
out.append(f"{Colors.YELLOW}  ❌ {smtp.get('message', 'No verificado')}")

disp = data.get('disposable', {})
out.append(f"\n{Colors.CYAN}📌 DOMINIO DESECHABLE:")
out.append(f"{Colors.WHITE}  {'⚠ SÍ' if disp.get('is_disposable') else '✅ NO'}")

spoof = data.get('spoofing', {})
out.append(f"\n{Colors.CYAN}📌 SEGURIDAD EMAIL:")
out.append(f"{Colors.WHITE}  SPF: {'✅' if spoof.get('has_spf') else '❌'}")
out.append(f"{Colors.WHITE}  DKIM: {'✅' if spoof.get('has_dkim') else '❌'}")
out.append(f"{Colors.WHITE}  DMARC: {'✅' if spoof.get('has_dmarc') else '❌'}")
return '\n'.join(out)

# ==========================================================
# PHONE ANALYZER
# ==========================================================
class PhoneAnalyzer:
def __init__(self):
self.cache = cache
self.coords = {
'ES': (40.4168, -3.7038), 'US': (37.7749, -122.4194), 'UK': (51.5074, -0.1278),
'FR': (48.8566, 2.3522), 'DE': (52.5200, 13.4050), 'MX': (19.4326, -99.1332),
'AR': (-34.6037, -58.3816), 'CO': (4.7110, -74.0721), 'IT': (41.9028, 12.4964),
'PT': (38.7223, -9.1393), 'NL': (52.3676, 4.9041), 'BE': (50.8503, 4.3517),
}

def analyze(self, number: str) -> Dict:
parsed = self._parse(number)
if not parsed.get('valid'):
return {'error': 'Número inválido'}
e164 = parsed['e164']
result = {
'number': number,
'timestamp': datetime.now().isoformat(),
'data': {
'basic': {
'country': parsed['country'],
'operator': parsed['operator'],
'location': parsed['location'],
'type': parsed['type']
},
'geo': self._geo(parsed),
'spam': self._spam(e164)
}
}
return result

def _parse(self, number: str) -> Dict:
key = f"parse_{number}"
cached = cache.get(key)
if cached: return cached
r = {'valid': False, 'e164': None, 'country': None, 'operator': 'Desconocido',
'location': 'No disponible', 'type': 'Desconocido'}
try:
p = phonenumbers.parse(number, None)
if phonenumbers.is_valid_number(p):
r['valid'] = True
r['e164'] = phonenumbers.format_number(p, phonenumbers.PhoneNumberFormat.E164)
r['country'] = phonenumbers.region_code_for_number(p)
r['operator'] = carrier.name_for_number(p, "es") or 'Desconocido'
r['location'] = geocoder.description_for_number(p, "es") or 'No disponible'
tipos = {phonenumbers.PhoneNumberType.MOBILE: 'Móvil',
phonenumbers.PhoneNumberType.FIXED_LINE: 'Fijo',
phonenumbers.PhoneNumberType.VOIP: 'VoIP'}
r['type'] = tipos.get(phonenumbers.number_type(p), 'Desconocido')
except: pass
cache.set(key, r, 86400)
return r

def _geo(self, parsed: Dict) -> Dict:
r = {'lat': None, 'lon': None}
if parsed.get('country') in self.coords:
r['lat'], r['lon'] = self.coords[parsed['country']]
return r

def _spam(self, e164: str) -> Dict:
key = f"spam_{e164}"
cached = cache.get(key)
if cached: return cached
r = {'reported': False, 'reports': 0, 'status': 'No verificado'}
try:
resp = requests.get(f"https://api.spamcalls.net/v1/phone/{e164}", timeout=5)
if resp.status_code == 200:
d = resp.json()
r['reported'] = d.get('reported', False)
r['reports'] = d.get('reports', 0)
r['status'] = 'Verificado'
except:
r['status'] = '⚠ No se pudo verificar'
cache.set(key, r, 86400)
return r

def format(self, results: Dict) -> str:
if 'error' in results:
return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"
out = []
data = results.get('data', {})
basic = data.get('basic', {})
header("📱 ANÁLISIS DE TELÉFONO")
out.append(f"{Colors.CYAN}Número: {Colors.WHITE}{results['number']}")
out.append(f"{Colors.CYAN}País: {Colors.WHITE}{basic.get('country', 'N/A')}")
out.append(f"{Colors.CYAN}Operador: {Colors.WHITE}{basic.get('operator', 'N/A')}")
out.append(f"{Colors.CYAN}Ubicación: {Colors.WHITE}{basic.get('location', 'N/A')}")
out.append(f"{Colors.CYAN}Tipo: {Colors.WHITE}{basic.get('type', 'N/A')}")
geo = data.get('geo', {})
if geo.get('lat'):
out.append(f"\n{Colors.CYAN}📍 UBICACIÓN:")
out.append(f"{Colors.WHITE}  Coordenadas: {geo['lat']}, {geo['lon']}")
out.append(f"{Colors.WHITE}  Mapa: https://www.google.com/maps?q={geo['lat']},{geo['lon']}")
spam = data.get('spam', {})
out.append(f"\n{Colors.CYAN}🚫 REPUTACIÓN SPAM:")
if spam.get('status') == '⚠ No se pudo verificar':
out.append(f"{Colors.YELLOW}  {spam['status']}")
elif spam.get('reported'):
out.append(f"{Colors.RED}  ⚠ Reportado ({spam.get('reports', 0)} reportes)")
else:
out.append(f"{Colors.GREEN}  ✅ Sin reportes")
out.append(f"\n{Colors.GREEN}✅ Verificación ética - Sin mensajes enviados{Colors.RESET}")
return '\n'.join(out)

# ==========================================================
# DOMAIN ANALYZER
# ==========================================================
class DomainAnalyzer:
def __init__(self):
self.cache = cache

def analyze(self, domain: str) -> Dict:
domain = domain.lower().strip()
result = {'domain': domain, 'timestamp': datetime.now().isoformat(), 'data': {}}
result['data']['whois'] = self._whois(domain)
result['data']['dns'] = self._dns(domain)
result['data']['ssl'] = self._ssl(domain)
return result

def _whois(self, domain: str) -> Dict:
key = f"whois_{domain}"
cached = cache.get(key)
if cached: return cached
r = {'registrar': None, 'creation': None, 'expiration': None, 'nameservers': []}
try:
w = whois.whois(domain)
r['registrar'] = str(w.registrar) if w.registrar else None
r['creation'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else None
r['expiration'] = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else None
r['nameservers'] = w.name_servers if w.name_servers else []
except: pass
cache.set(key, r, 86400)
return r

def _dns(self, domain: str) -> Dict:
key = f"dns_{domain}"
cached = cache.get(key)
if cached: return cached
r = {'A': [], 'MX': [], 'NS': []}
for tipo in ['A', 'MX', 'NS']:
try:
answers = dns.resolver.resolve(domain, tipo)
for ans in answers:
if tipo == 'MX':
r[tipo].append({'exchange': str(ans.exchange), 'preference': ans.preference})
else:
r[tipo].append(str(ans))
except: pass
cache.set(key, r, 3600)
return r

def _ssl(self, domain: str) -> Dict:
key = f"ssl_{domain}"
cached = cache.get(key)
if cached: return cached
r = {'valid': False, 'issuer': None, 'expires': None}
try:
ctx = ssl.create_default_context()
with socket.create_connection((domain, 443), timeout=10) as sock:
with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
cert = ssock.getpeercert()
r['valid'] = True
r['issuer'] = dict(x[0] for x in cert['issuer']).get('organizationName', 'Desconocido')
r['expires'] = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z').isoformat()
except: pass
cache.set(key, r, 86400)
return r

def format(self, results: Dict) -> str:
out = []
data = results.get('data', {})
header("🌐 ANÁLISIS DE DOMINIO")
out.append(f"{Colors.CYAN}Dominio: {Colors.WHITE}{results['domain']}")
whois = data.get('whois', {})
if whois.get('registrar'):
out.append(f"\n{Colors.CYAN}📋 WHOIS:")
out.append(f"{Colors.WHITE}  Registrador: {whois['registrar']}")
if whois.get('creation'):
out.append(f"{Colors.WHITE}  Creación: {whois['creation']}")
if whois.get('expiration'):
out.append(f"{Colors.WHITE}  Expiración: {whois['expiration']}")
if whois.get('nameservers'):
out.append(f"{Colors.WHITE}  DNS: {', '.join(whois['nameservers'][:3])}")
else:
out.append(f"\n{Colors.CYAN}📋 WHOIS:")
out.append(f"{Colors.YELLOW}  ⚠ No disponible")
dns = data.get('dns', {})
out.append(f"\n{Colors.CYAN}📌 REGISTROS DNS:")
for tipo in ['A', 'MX', 'NS']:
if dns.get(tipo):
values = dns[tipo][:3]
if tipo == 'MX':
values = [f"{v['exchange']} (Prio: {v['preference']})" for v in values]
out.append(f"{Colors.WHITE}  {tipo}: {', '.join(str(v) for v in values)}")
else:
out.append(f"{Colors.GRAY}  {tipo}: No encontrado")
ssl = data.get('ssl', {})
out.append(f"\n{Colors.CYAN}🔒 SSL:")
if ssl.get('valid'):
out.append(f"{Colors.GREEN}  ✅ Válido")
out.append(f"{Colors.WHITE}  Emisor: {ssl.get('issuer', 'N/A')}")
out.append(f"{Colors.WHITE}  Expira: {ssl.get('expires', 'N/A')}")
else:
out.append(f"{Colors.RED}  ❌ No válido o sin HTTPS")
return '\n'.join(out)

# ==========================================================
# LISTA DE ~80 SITIOS VERIFICADOS (SIN API)
# ==========================================================
def cargar_plataformas_lyra() -> List[Dict]:
return [
{'name':'Twitter','url':'https://twitter.com/{username}'},
{'name':'Instagram','url':'https://www.instagram.com/{username}'},
{'name':'Facebook','url':'https://www.facebook.com/{username}'},
{'name':'YouTube','url':'https://www.youtube.com/@{username}'},
{'name':'TikTok','url':'https://www.tiktok.com/@{username}'},
{'name':'Pinterest','url':'https://www.pinterest.com/{username}'},
{'name':'Reddit','url':'https://www.reddit.com/user/{username}'},
{'name':'Tumblr','url':'https://{username}.tumblr.com'},
{'name':'VK','url':'https://vk.com/{username}'},
{'name':'Mastodon','url':'https://mastodon.social/@{username}'},
{'name':'Threads','url':'https://www.threads.net/@{username}'},
{'name':'Bluesky','url':'https://bsky.app/profile/{username}'},
{'name':'Minds','url':'https://www.minds.com/{username}'},
{'name':'Gab','url':'https://gab.com/{username}'},
{'name':'MeWe','url':'https://mewe.com/i/{username}'},
{'name':'Rumble','url':'https://rumble.com/user/{username}'},
{'name':'Odysee','url':'https://odysee.com/@{username}'},
{'name':'Weibo','url':'https://www.weibo.com/{username}'},
{'name':'Odnoklassniki','url':'https://ok.ru/{username}'},
{'name':'Mail.ru','url':'https://my.mail.ru/{username}'},
{'name':'Flickr','url':'https://www.flickr.com/people/{username}'},
{'name':'500px','url':'https://500px.com/{username}'},
{'name':'Imgur','url':'https://imgur.com/user/{username}'},
{'name':'Dribbble','url':'https://dribbble.com/{username}'},
{'name':'Behance','url':'https://www.behance.net/{username}'},
{'name':'ArtStation','url':'https://www.artstation.com/{username}'},
{'name':'DeviantArt','url':'https://{username}.deviantart.com'},
{'name':'Pixiv','url':'https://www.pixiv.net/en/users/{username}'},
{'name':'Medium','url':'https://medium.com/@{username}'},
{'name':'Dev.to','url':'https://dev.to/{username}'},
{'name':'Hashnode','url':'https://hashnode.com/@{username}'},
{'name':'WordPress','url':'https://{username}.wordpress.com'},
{'name':'Blogger','url':'https://{username}.blogspot.com'},
{'name':'Substack','url':'https://{username}.substack.com'},
{'name':'Ghost','url':'https://{username}.ghost.io'},
{'name':'Notion','url':'https://{username}.notion.site'},
{'name':'Squarespace','url':'https://{username}.squarespace.com'},
{'name':'Wix','url':'https://{username}.wixsite.com'},
{'name':'About.me','url':'https://about.me/{username}'},
{'name':'Gravatar','url':'https://en.gravatar.com/{username}'},
{'name':'Keybase','url':'https://keybase.io/{username}'},
{'name':'GitHub','url':'https://github.com/{username}'},
{'name':'GitLab','url':'https://gitlab.com/{username}'},
{'name':'Bitbucket','url':'https://bitbucket.org/{username}'},
{'name':'SourceForge','url':'https://sourceforge.net/u/{username}'},
{'name':'CodePen','url':'https://codepen.io/{username}'},
{'name':'JSFiddle','url':'https://jsfiddle.net/user/{username}'},
{'name':'Replit','url':'https://replit.com/@{username}'},
{'name':'Glitch','url':'https://glitch.com/@{username}'},
{'name':'CodeSandbox','url':'https://codesandbox.io/u/{username}'},
{'name':'StackBlitz','url':'https://stackblitz.com/@{username}'},
{'name':'Pastebin','url':'https://pastebin.com/u/{username}'},
{'name':'LeetCode','url':'https://leetcode.com/{username}'},
{'name':'HackerRank','url':'https://www.hackerrank.com/{username}'},
{'name':'CodeWars','url':'https://www.codewars.com/users/{username}'},
{'name':'Kaggle','url':'https://www.kaggle.com/{username}'},
{'name':'StackOverflow','url':'https://stackoverflow.com/users/{username}'},
{'name':'HackerNews','url':'https://news.ycombinator.com/user?id={username}'},
{'name':'Quora','url':'https://www.quora.com/profile/{username}'},
{'name':'Disqus','url':'https://disqus.com/by/{username}'},
{'name':'BitcoinTalk','url':'https://bitcointalk.org/index.php?action=profile;u={username}'},
{'name':'Genius','url':'https://genius.com/{username}'},
{'name':'Goodreads','url':'https://www.goodreads.com/user/show/{username}'},
{'name':'Letterboxd','url':'https://letterboxd.com/{username}'},
{'name':'IMDb','url':'https://www.imdb.com/user/{username}'},
{'name':'Twitch','url':'https://www.twitch.tv/{username}'},
{'name':'Kick','url':'https://kick.com/{username}'},
{'name':'Vimeo','url':'https://vimeo.com/{username}'},
{'name':'Dailymotion','url':'https://www.dailymotion.com/{username}'},
{'name':'LBRY','url':'https://lbry.tv/@{username}'},
{'name':'SoundCloud','url':'https://soundcloud.com/{username}'},
{'name':'Spotify','url':'https://open.spotify.com/user/{username}'},
{'name':'Bandcamp','url':'https://{username}.bandcamp.com'},
{'name':'Mixcloud','url':'https://www.mixcloud.com/{username}'},
{'name':'LastFM','url':'https://last.fm/user/{username}'},
{'name':'Steam','url':'https://steamcommunity.com/id/{username}'},
{'name':'PlayStation','url':'https://psnprofiles.com/{username}'},
{'name':'Xbox','url':'https://xboxgamertag.com/search/{username}'},
{'name':'Roblox','url':'https://www.roblox.com/user.aspx?username={username}'},
{'name':'EpicGames','url':'https://www.epicgames.com/profile/{username}'},
{'name':'OpenSea','url':'https://opensea.io/{username}'},
{'name':'Rarible','url':'https://rarible.com/{username}'},
{'name':'Foundation','url':'https://foundation.app/@{username}'},
{'name':'Etherscan','url':'https://etherscan.io/address/{username}'},
{'name':'Amazon','url':'https://www.amazon.com/gp/profile/{username}'},
{'name':'eBay','url':'https://www.ebay.com/usr/{username}'},
{'name':'Etsy','url':'https://www.etsy.com/shop/{username}'},
{'name':'AliExpress','url':'https://www.aliexpress.com/store/{username}'},
{'name':'Yelp','url':'https://www.yelp.com/user_details?userid={username}'},
{'name':'Upwork','url':'https://www.upwork.com/freelancers/{username}'},
{'name':'Fiverr','url':'https://www.fiverr.com/{username}'},
{'name':'Freelancer','url':'https://www.freelancer.com/u/{username}'},
{'name':'Toptal','url':'https://www.toptal.com/profile/{username}'},
{'name':'Glassdoor','url':'https://www.glassdoor.com/profile/{username}'},
{'name':'Tinder','url':'https://www.tinder.com/@{username}'},
{'name':'Bumble','url':'https://bumble.com/@{username}'},
{'name':'OKCupid','url':'https://www.okcupid.com/profile/{username}'},
{'name':'Strava','url':'https://www.strava.com/athletes/{username}'},
{'name':'Fitbit','url':'https://www.fitbit.com/user/{username}'},
{'name':'MyFitnessPal','url':'https://www.myfitnesspal.com/profile/{username}'},
{'name':'Airbnb','url':'https://www.airbnb.com/users/show/{username}'},
{'name':'Booking','url':'https://booking.com/profile/{username}'},
{'name':'TripAdvisor','url':'https://www.tripadvisor.com/profile/{username}'},
{'name':'Coursera','url':'https://www.coursera.org/user/{username}'},
{'name':'Udemy','url':'https://www.udemy.com/user/{username}'},
{'name':'KhanAcademy','url':'https://www.khanacademy.org/profile/{username}'},
{'name':'ResearchGate','url':'https://www.researchgate.net/profile/{username}'},
{'name':'Academia.edu','url':'https://www.academia.edu/{username}'},
{'name':'ORCID','url':'https://orcid.org/{username}'},
{'name':'Taringa','url':'https://taringa.net/{username}'},
{'name':'ForoCoches','url':'https://forocoches.com/{username}'},
{'name':'Meneame','url':'https://meneame.net/{username}'},
{'name':'Douban','url':'https://douban.com/people/{username}'},
{'name':'Zhihu','url':'https://zhihu.com/people/{username}'},
{'name':'Huaban','url':'https://huaban.com/{username}'},
{'name':'Lofter','url':'https://lofter.com/{username}'},
{'name':'Tieba','url':'https://tieba.baidu.com/home/main?un={username}'},
{'name':'HackTheBox','url':'https://www.hackthebox.com/profile/{username}'},
{'name':'TryHackMe','url':'https://tryhackme.com/p/{username}'},
{'name':'Root-me','url':'https://root-me.org/{username}'},
]

# ==========================================================
# INSTALADOR AUTOMÁTICO DE MAIGRET (SIN PIP)
# ==========================================================
def instalar_maigret():
"""Instala Maigret automáticamente clonando el repositorio."""
print(f"{Colors.YELLOW}⚠ Maigret no encontrado. Instalando automáticamente...{Colors.RESET}")

venv_dir = Path("maigret_env")
if not venv_dir.exists():
print(f"{Colors.CYAN}[1/4] Creando entorno virtual...{Colors.RESET}")
venv.create(venv_dir, with_pip=True)

if sys.platform == "win32":
python_path = venv_dir / "Scripts" / "python.exe"
pip_path = venv_dir / "Scripts" / "pip.exe"
bin_path = venv_dir / "Scripts" / "maigret.exe"
else:
python_path = venv_dir / "bin" / "python"
pip_path = venv_dir / "bin" / "pip"
bin_path = venv_dir / "bin" / "maigret"

maigret_dir = Path("maigret_repo")
if not maigret_dir.exists():
print(f"{Colors.CYAN}[2/4] Clonando repositorio de Maigret...{Colors.RESET}")
subprocess.run(["git", "clone", "https://github.com/soxoj/maigret.git", str(maigret_dir)], check=False)

print(f"{Colors.CYAN}[3/4] Instalando dependencias de Maigret...{Colors.RESET}")
subprocess.run([str(pip_path), "install", "-r", str(maigret_dir / "requirements.txt")], check=False)
subprocess.run([str(pip_path), "install", "-e", str(maigret_dir)], check=False)

print(f"{Colors.CYAN}[4/4] Verificando instalación...{Colors.RESET}")
if bin_path.exists():
print(f"{Colors.GREEN}✅ Maigret instalado correctamente en: {venv_dir}{Colors.RESET}")
return str(python_path), str(bin_path)
else:
# Fallback: usar python -m maigret
result = subprocess.run([str(python_path), "-m", "maigret", "--version"], capture_output=True, text=True)
if result.returncode == 0:
print(f"{Colors.GREEN}✅ Maigret instalado como módulo en: {venv_dir}{Colors.RESET}")
return str(python_path), None
else:
print(f"{Colors.RED}❌ Error instalando Maigret. Intenta manualmente: pip install maigret{Colors.RESET}")
return None, None

# ==========================================================
# USERNAME TRACKER CON MAIGRET FUNCIONAL
# ==========================================================
class UsernameTracker:
def __init__(self):
self.cache = cache
self.timeout = 15
self.max_threads = 30
self.user_agents = [
'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
]
self.platforms = cargar_plataformas_lyra()
self.maigret_available, self.maigret_cmd = self._setup_maigret()
self.sherlock_available = self._check_sherlock()

def _setup_maigret(self):
"""Configura Maigret (busca o instala automáticamente)."""
# 1. Buscar en PATH
maigret_path = shutil.which('maigret')
if maigret_path:
return True, [maigret_path]

# 2. Buscar en ~/.local/bin
local_bin = Path.home() / '.local' / 'bin' / 'maigret'
if local_bin.exists():
return True, [str(local_bin)]

# 3. Probar ejecución directa
try:
subprocess.run(['maigret', '--version'], capture_output=True, timeout=5)
return True, ['maigret']
except:
pass

# 4. Intentar instalar automáticamente
print(f"{Colors.YELLOW}⚠ Maigret no encontrado. Intentando instalación automática...{Colors.RESET}")
python_path, bin_path = instalar_maigret()
if bin_path:
return True, [bin_path]
elif python_path:
return True, [python_path, '-m', 'maigret']

return False, None

def _check_sherlock(self):
"""Detecta Sherlock."""
if shutil.which('sherlock'):
return True
if (Path.home() / '.local' / 'bin' / 'sherlock').exists():
return True
try:
subprocess.run(['sherlock', '--help'], capture_output=True, timeout=5)
return True
except:
pass
return False

def track_lyra(self, username: str) -> Dict:
cache_key = f"lyra_{username}"
cached = cache.get(cache_key)
if cached:
return cached

username = username.strip().lower()
results = {
'username': username,
'engine': f'LYRA Engine ({len(self.platforms)} sitios)',
'timestamp': datetime.now().isoformat(),
'total_platforms': len(self.platforms),
'found': 0,
'platforms': []
}

with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
futures = {executor.submit(self._check_site, platform, username): platform for platform in self.platforms}
for future in as_completed(futures):
try:
result = future.result()
if result:
results['platforms'].append(result)
results['found'] += 1
except:
pass

results['platforms'] = sorted(results['platforms'], key=lambda x: x['name'])
cache.set(cache_key, results, 3600)
return results

def _check_site(self, platform: Dict, username: str) -> Optional[Dict]:
url = platform['url'].format(username=username)
try:
headers = {
'User-Agent': random.choice(self.user_agents),
'Accept': 'text/html,application/xhtml+xml',
}
response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
if response.status_code == 200:
html = response.text.lower()
not_found = ['not found', 'does not exist', 'page not found', '404', 'user not found', 'profile not found']
if not any(kw in html for kw in not_found):
return {'name': platform['name'], 'url': url, 'status': response.status_code}
except:
pass
return None

def track_maigret(self, username: str) -> Dict:
"""Ejecuta Maigret con fallback si falla JSON."""
if not self.maigret_available:
return {'error': 'Maigret no está disponible. Intenta instalarlo manualmente con: pip install maigret'}

cache_key = f"maigret_{username}"
cached = cache.get(cache_key)
if cached:
return cached

results = {
'username': username,
'engine': 'Maigret (3000+ sitios)',
'timestamp': datetime.now().isoformat(),
'found': 0,
'platforms': [],
'raw_output': ''
}

# Intento con JSON
cmd = self.maigret_cmd + [username, '--json', 'full']  # 'full' es el argumento esperado
try:
print(f"{Colors.GRAY}Ejecutando: {' '.join(cmd)}{Colors.RESET}")
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

if proc.returncode == 0 and proc.stdout:
try:
data = json.loads(proc.stdout)
for site, info in data.get('sites', {}).items():
if info.get('status') == 'claimed':
results['platforms'].append({
'name': site,
'url': info.get('url', ''),
'status': info.get('status')
})
results['found'] += 1
cache.set(cache_key, results, 3600)
return results
except json.JSONDecodeError:
# Si falla JSON, usar fallback
pass
else:
results['raw_output'] = proc.stderr[:2000] if proc.stderr else proc.stdout[:2000]
except Exception as e:
results['raw_output'] = f"Error: {str(e)}"

# Fallback: parsear salida de texto (sin --json)
print(f"{Colors.GRAY}Fallback: parseando salida de texto...{Colors.RESET}")
try:
cmd = self.maigret_cmd + [username]
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
if proc.returncode == 0:
lines = proc.stdout.splitlines()
for line in lines:
# Buscar líneas con formato: "[+] Site: URL"
match = re.search(r'\[\+\]\s+([^:]+):\s*(https?://[^\s]+)', line)
if match:
site_name = match.group(1).strip()
url = match.group(2).strip()
results['platforms'].append({'name': site_name, 'url': url, 'status': 'found'})
results['found'] += 1
if results['found'] == 0:
results['raw_output'] = proc.stdout[:2000] if proc.stdout else "Sin salida útil"
else:
results['raw_output'] = proc.stderr[:2000] if proc.stderr else "Comando falló"
except Exception as e:
results['raw_output'] = f"Error en fallback: {str(e)}"

cache.set(cache_key, results, 3600)
return results

def track_sherlock(self, username: str) -> Dict:
"""Ejecuta Sherlock."""
if not self.sherlock_available:
return {'error': 'Sherlock no está instalado. Instálalo con: pip install sherlock-project'}

cache_key = f"sherlock_{username}"
cached = cache.get(cache_key)
if cached:
return cached

results = {
'username': username,
'engine': 'Sherlock (479 sitios)',
'timestamp': datetime.now().isoformat(),
'found': 0,
'platforms': [],
'raw_output': ''
}

try:
cmd = ['sherlock', username, '--print-found']
print(f"{Colors.GRAY}Ejecutando: {' '.join(cmd)}{Colors.RESET}")
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

if proc.returncode == 0:
for line in proc.stdout.splitlines():
line = line.strip()
if line and 'http' in line:
parts = line.split(':', 1)
if len(parts) == 2:
site_name = parts[0].strip()
url = parts[1].strip()
results['platforms'].append({'name': site_name, 'url': url, 'status': 'found'})
results['found'] += 1
if not results['platforms']:
results['raw_output'] = proc.stdout[:2000]
else:
results['raw_output'] = proc.stderr[:2000] if proc.stderr else proc.stdout[:2000]

except subprocess.TimeoutExpired:
results['error'] = 'Timeout (180s) - Sherlock tardó demasiado'
except FileNotFoundError:
results['error'] = 'Sherlock no encontrado. Instálalo con: pip install sherlock-project'
except Exception as e:
results['error'] = f'Error ejecutando Sherlock: {str(e)}'

cache.set(cache_key, results, 3600)
return results

def format(self, results: Dict) -> str:
if 'error' in results:
return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"

out = []
header(f"👤 USERNAME TRACKING - {results.get('engine', 'Desconocido')}")
out.append(f"{Colors.CYAN}Username: {Colors.WHITE}{results['username']}")
out.append(f"{Colors.CYAN}Motor: {Colors.WHITE}{results.get('engine', 'Desconocido')}")
out.append(f"{Colors.CYAN}Encontrado en: {Colors.GREEN if results['found'] > 0 else Colors.RED}{results['found']} plataformas{Colors.RESET}")

if results.get('raw_output'):
out.append(f"\n{Colors.CYAN}📌 SALIDA CRUDA:{Colors.RESET}")
out.append(f"{Colors.GRAY}{results['raw_output'][:2000]}{Colors.RESET}")

if results['found'] > 0:
out.append(f"\n{Colors.CYAN}📌 PLATAFORMAS ENCONTRADAS:{Colors.RESET}")
for i, p in enumerate(results['platforms'], 1):
out.append(f"{Colors.GREEN}[{i}]{Colors.RESET} {Colors.WHITE}{p['name']}{Colors.RESET}")
if p.get('url'):
out.append(f"   {Colors.GRAY}URL: {p['url']}{Colors.RESET}")
else:
out.append(f"\n{Colors.YELLOW}⚠ No se encontró el username en ninguna plataforma{Colors.RESET}")

return '\n'.join(out)

# ==========================================================
# CLASE PRINCIPAL LYRA
# ==========================================================
class LYRA:
def __init__(self):
self.email = EmailAnalyzer()
self.phone = PhoneAnalyzer()
self.domain = DomainAnalyzer()
self.username = UsernameTracker()

def analyze(self, target: str) -> Dict:
tipo = detect_type(target)
if tipo == 'email':
return self.email.analyze(target)
elif tipo == 'phone':
return self.phone.analyze(target)
elif tipo == 'domain':
return self.domain.analyze(target)
elif tipo == 'username':
if target.startswith('@'):
target = target[1:]
return self.username.track_lyra(target)
else:
return {'error': 'No se pudo determinar el tipo'}

# ==========================================================
# INTERFAZ
# ==========================================================
class LyraUI:
def __init__(self):
self.lyra = LYRA()
self.running = True

def clear(self):
os.system('clear' if os.name == 'posix' else 'cls')

def banner(self):
    total = len(self.lyra.username.platforms)
    maigret_ok = "✅" if self.lyra.username.maigret_available else "❌"
    sherlock_ok = "✅" if self.lyra.username.sherlock_available else "❌"
    print(f"""
{Colors.ORANGE}╔══════════════════════════════════════════════════════════════════╗
{Colors.ORANGE}║{Colors.GREEN}       ██╗    ██╗   ██╗██████╗  █████╗               {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗              {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║     ╚████╔╝ ██████╔╝███████║              {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║      ╚██╔╝  ██╔══██╗██╔══██║              {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ███████╗  ██║   ██║  ██║██║  ██║              {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝              {Colors.ORANGE}║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.CYAN}                 ✧  L Y R A  P R O  ✧                {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.YELLOW}           🔍 OSINT Ético y Funcional              {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GRAY}                  ⚖️ Uso exclusivamente legal         {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.WHITE}         📊 {str(total).rjust(3)} sitios (motor LYRA)             {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.WHITE}         {maigret_ok} Maigret (3000+ sitios)        {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.WHITE}         {sherlock_ok} Sherlock (479 sitios)        {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}         ✅ SIN API - SIN LOGIN - SOLO PÚBLICO      {Colors.ORANGE}║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
""")

def menu(self):
total = len(self.lyra.username.platforms)
print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════╗")
print(f"{Colors.CYAN}║                    M E N Ú   L Y R A                      ║")
print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
print(f"{Colors.ORANGE}[1]{Colors.RESET} 📱 Análisis de Teléfono")
print(f"{Colors.ORANGE}[2]{Colors.RESET} 📧 Análisis de Email")
print(f"{Colors.ORANGE}[3]{Colors.RESET} 🌐 Análisis de Dominio")
print(f"{Colors.ORANGE}[4]{Colors.RESET} 👤 Username Tracking (LYRA - {total} sitios)")
print(f"{Colors.ORANGE}[5]{Colors.RESET} ⚡ Username Tracking (Maigret - 3000+ sitios)")
print(f"{Colors.ORANGE}[6]{Colors.RESET} ⚡ Username Tracking (Sherlock - 479 sitios)")
print(f"{Colors.ORANGE}[7]{Colors.RESET} 🤖 Análisis Automático")
print(f"{Colors.ORANGE}[0]{Colors.RESET} 🚪 Salir")

def phone_menu(self):
self.clear()
header("📱 ANÁLISIS DE TELÉFONO")
print(f"{Colors.GREEN}✅ Sin WhatsApp/Telegram - Solo datos públicos{Colors.RESET}\n")
number = input(f"{Colors.WHITE}Número (ej. +34123456789): {Colors.RESET}").strip()
if not number:
print(f"{Colors.RED}Número inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
results = self.lyra.phone.analyze(number)
if 'error' in results:
print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
else:
print(self.lyra.phone.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def email_menu(self):
self.clear()
header("📧 ANÁLISIS DE EMAIL")
email = input(f"{Colors.WHITE}Email: {Colors.RESET}").strip()
if not email or '@' not in email:
print(f"{Colors.RED}Email inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
results = self.lyra.email.analyze(email)
if 'error' in results:
print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
else:
print(self.lyra.email.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def domain_menu(self):
self.clear()
header("🌐 ANÁLISIS DE DOMINIO")
domain = input(f"{Colors.WHITE}Dominio: {Colors.RESET}").strip()
if not domain:
print(f"{Colors.RED}Dominio inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
results = self.lyra.domain.analyze(domain)
if 'error' in results:
print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
else:
print(self.lyra.domain.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def username_menu_lyra(self):
self.clear()
total = len(self.lyra.username.platforms)
header(f"👤 USERNAME TRACKING (LYRA - {total} sitios)")
username = input(f"{Colors.WHITE}Username: {Colors.RESET}").strip()
if not username:
print(f"{Colors.RED}Username inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Buscando en {total} sitios...{Colors.RESET}")
results = self.lyra.username.track_lyra(username)
print(self.lyra.username.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def username_menu_maigret(self):
self.clear()
header("⚡ USERNAME TRACKING (Maigret - 3000+ sitios)")
if not self.lyra.username.maigret_available:
print(f"{Colors.YELLOW}⚠ Maigret no está disponible. Instalando automáticamente...{Colors.RESET}")
python_path, bin_path = instalar_maigret()
if bin_path:
self.lyra.username.maigret_available = True
self.lyra.username.maigret_cmd = [bin_path]
print(f"{Colors.GREEN}✅ Maigret instalado correctamente. Vuelve a intentarlo.{Colors.RESET}")
elif python_path:
self.lyra.username.maigret_available = True
self.lyra.username.maigret_cmd = [python_path, '-m', 'maigret']
print(f"{Colors.GREEN}✅ Maigret instalado como módulo. Vuelve a intentarlo.{Colors.RESET}")
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
username = input(f"{Colors.WHITE}Username: {Colors.RESET}").strip()
if not username:
print(f"{Colors.RED}Username inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Ejecutando Maigret (puede tardar varios minutos)...{Colors.RESET}")
results = self.lyra.username.track_maigret(username)
print(self.lyra.username.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def username_menu_sherlock(self):
self.clear()
header("⚡ USERNAME TRACKING (Sherlock - 479 sitios)")
if not self.lyra.username.sherlock_available:
print(f"{Colors.YELLOW}⚠ Sherlock no está instalado. Instálalo con: pip install sherlock-project{Colors.RESET}")
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
username = input(f"{Colors.WHITE}Username: {Colors.RESET}").strip()
if not username:
print(f"{Colors.RED}Username inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Ejecutando Sherlock (puede tardar varios minutos)...{Colors.RESET}")
results = self.lyra.username.track_sherlock(username)
print(self.lyra.username.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def auto_menu(self):
self.clear()
header("🤖 ANÁLISIS AUTOMÁTICO")
target = input(f"{Colors.WHITE}Target (email, teléfono, dominio o @username): {Colors.RESET}").strip()
if not target:
print(f"{Colors.RED}Target inválido{Colors.RESET}")
input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
return
print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
results = self.lyra.analyze(target)
if 'error' in results:
print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
elif 'number' in results:
print(self.lyra.phone.format(results))
elif 'email' in results:
print(self.lyra.email.format(results))
elif 'domain' in results:
print(self.lyra.domain.format(results))
elif 'username' in results:
print(self.lyra.username.format(results))
input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")

def run(self):
while self.running:
self.clear()
self.banner()
self.menu()
opcion = input(f"\n{Colors.ORANGE}Elige una opción: {Colors.RESET}").strip()
if opcion == "1":
self.phone_menu()
elif opcion == "2":
self.email_menu()
elif opcion == "3":
self.domain_menu()
elif opcion == "4":
self.username_menu_lyra()
elif opcion == "5":
self.username_menu_maigret()
elif opcion == "6":
self.username_menu_sherlock()
elif opcion == "7":
self.auto_menu()
elif opcion == "0":
print(f"\n{Colors.GREEN}👋 ¡Hasta luego!{Colors.RESET}")
self.running = False
else:
print(f"\n{Colors.RED}Opción inválida{Colors.RESET}")
time.sleep(1)

# ==========================================================
# MAIN
# ==========================================================
def main():
try:
ui = LyraUI()
ui.run()
except KeyboardInterrupt:
print(f"\n{Colors.YELLOW}⚠ Interrupción. ¡Hasta luego!{Colors.RESET}")
except Exception as e:
print(f"\n{Colors.RED}Error: {str(e)}{Colors.RESET}")

if __name__ == '__main__':
main()
