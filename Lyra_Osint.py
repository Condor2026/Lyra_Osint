#!/usr/bin/python
# ==========================================================
# LYRA - OSINT ÉTICO (FUNCIONAL)
# ==========================================================

import json
import requests
import time
import os
import re
import sqlite3
import phonenumbers
from phonenumbers import carrier, geocoder
from datetime import datetime
from pathlib import Path

# ==========================================================
# COLORES
# ==========================================================
class C:
    R = '\033[91m'
    G = '\033[92m'
    Y = '\033[93m'
    O = '\033[38;5;208m'
    W = '\033[97m'
    C = '\033[96m'
    GR = '\033[90m'
    RST = '\033[0m'

def p(t, c=C.W): print(f"{c}{t}{C.RST}")

def header(t):
    print(f"\n{C.C}╔{'═'*50}╗{C.RST}")
    print(f"{C.C}║{t.center(50)}║{C.RST}")
    print(f"{C.C}╚{'═'*50}╝{C.RST}")

# ==========================================================
# CACHE (CORREGIDO)
# ==========================================================
class Cache:
    def __init__(self):
        Path("cache").mkdir(exist_ok=True)
        self.db = sqlite3.connect("cache/cache.db", check_same_thread=False)
        # TABLA CORRECTA
        self.db.execute('CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, timestamp INTEGER, ttl INTEGER)')
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

# ==========================================================
# ANALIZADOR DE TELÉFONO
# ==========================================================
class PhoneAnalyzer:
    def __init__(self):
        self.cache = Cache()
        self.coords = {
            'ES': (40.4168, -3.7038), 'US': (37.7749, -122.4194), 'UK': (51.5074, -0.1278),
            'FR': (48.8566, 2.3522), 'DE': (52.5200, 13.4050), 'MX': (19.4326, -99.1332),
            'AR': (-34.6037, -58.3816), 'CO': (4.7110, -74.0721), 'IT': (41.9028, 12.4964),
            'PT': (38.7223, -9.1393), 'NL': (52.3676, 4.9041), 'BE': (50.8503, 4.3517),
        }
    
    def analyze(self, number):
        parsed = self._parse(number)
        if not parsed.get('valid'):
            return {'error': 'Número inválido'}
        
        e164 = parsed['e164']
        
        return {
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
    
    def _parse(self, number):
        key = f"parse_{number}"
        cached = self.cache.get(key)
        if cached:
            return cached
        
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
                tipos = {
                    phonenumbers.PhoneNumberType.MOBILE: 'Móvil',
                    phonenumbers.PhoneNumberType.FIXED_LINE: 'Fijo',
                    phonenumbers.PhoneNumberType.VOIP: 'VoIP',
                }
                r['type'] = tipos.get(phonenumbers.number_type(p), 'Desconocido')
        except:
            pass
        
        self.cache.set(key, r, 86400)
        return r
    
    def _geo(self, parsed):
        r = {'lat': None, 'lon': None}
        if parsed.get('country') in self.coords:
            r['lat'], r['lon'] = self.coords[parsed['country']]
        return r
    
    def _spam(self, e164):
        key = f"spam_{e164}"
        cached = self.cache.get(key)
        if cached:
            return cached
        
        r = {'reported': False, 'reports': 0, 'status': 'No verificado'}
        try:
            resp = requests.get(f"https://api.spamcalls.net/v1/phone/{e164}", timeout=5)
            if resp.status_code == 200:
                d = resp.json()
                r['reported'] = d.get('reported', False)
                r['reports'] = d.get('reports', 0)
                r['status'] = 'Verificado'
        except:
            r['status'] = '⚠️ No se pudo verificar'
        
        self.cache.set(key, r, 86400)
        return r
    
    def format(self, results):
        if 'error' in results:
            return f"{C.R}Error: {results['error']}{C.RST}"
        
        out = []
        data = results.get('data', {})
        basic = data.get('basic', {})
        
        header("📱 ANÁLISIS DE TELÉFONO")
        out.append(f"{C.C}Número: {C.W}{results['number']}")
        out.append(f"{C.C}País: {C.W}{basic.get('country', 'N/A')}")
        out.append(f"{C.C}Operador: {C.W}{basic.get('operator', 'N/A')}")
        out.append(f"{C.C}Ubicación: {C.W}{basic.get('location', 'N/A')}")
        out.append(f"{C.C}Tipo: {C.W}{basic.get('type', 'N/A')}")
        
        geo = data.get('geo', {})
        if geo.get('lat'):
            out.append(f"\n{C.C}📍 UBICACIÓN:")
            out.append(f"{C.W}  Coordenadas: {geo['lat']}, {geo['lon']}")
            out.append(f"{C.W}  Mapa: https://www.google.com/maps?q={geo['lat']},{geo['lon']}")
        
        spam = data.get('spam', {})
        out.append(f"\n{C.C}🚫 REPUTACIÓN SPAM:")
        if spam.get('status') == '⚠️ No se pudo verificar':
            out.append(f"{C.Y}  {spam['status']}")
        elif spam.get('reported'):
            out.append(f"{C.R}  ⚠️ Reportado ({spam.get('reports', 0)} reportes)")
        else:
            out.append(f"{C.G}  ✅ Sin reportes")
        
        out.append(f"\n{C.G}✅ Verificación ética - Sin mensajes enviados{C.RST}")
        return '\n'.join(out)

# ==========================================================
# ANALIZADOR DE EMAIL
# ==========================================================
class EmailAnalyzer:
    def __init__(self):
        self.cache = Cache()
    
    def analyze(self, email):
        if '@' not in email:
            return {'error': 'Email inválido'}
        
        email = email.lower().strip()
        domain = email.split('@')[1]
        
        result = {
            'email': email,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'data': {}
        }
        
        result['data']['mx'] = self._mx(domain)
        result['data']['disposable'] = self._disposable(domain)
        
        return result
    
    def _mx(self, domain):
        key = f"mx_{domain}"
        cached = self.cache.get(key)
        if cached:
            return cached
        
        r = {'has_mx': False, 'records': []}
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'MX')
            r['has_mx'] = True
            for mx in answers:
                r['records'].append({'exchange': str(mx.exchange), 'preference': mx.preference})
            r['records'] = sorted(r['records'], key=lambda x: x['preference'])
        except:
            pass
        
        self.cache.set(key, r, 3600)
        return r
    
    def _disposable(self, domain):
        key = f"disp_{domain}"
        cached = self.cache.get(key)
        if cached:
            return cached
        
        dominios = {
            'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
            'throwawayemail.com', 'spamgourmet.com', 'yopmail.com', 'getnada.com',
            'fakeinbox.com', 'ghostmail.com', 'maildrop.cc'
        }
        r = {'is_disposable': domain in dominios}
        self.cache.set(key, r)
        return r
    
    def format(self, results):
        if 'error' in results:
            return f"{C.R}Error: {results['error']}{C.RST}"
        
        out = []
        data = results.get('data', {})
        
        header("📧 ANÁLISIS DE EMAIL")
        out.append(f"{C.C}Email: {C.W}{results['email']}")
        out.append(f"{C.C}Dominio: {C.W}{results['domain']}")
        
        mx = data.get('mx', {})
        out.append(f"\n{C.C}📌 SERVIDORES MX:")
        if mx.get('records'):
            for r in mx['records'][:3]:
                out.append(f"{C.W}  📤 {r['exchange']} (Prio: {r['preference']})")
        else:
            out.append(f"{C.Y}  ⚠️ No encontrados")
        
        disp = data.get('disposable', {})
        out.append(f"\n{C.C}📌 DOMINIO DESECHABLE:")
        out.append(f"{C.W}  {'⚠️ SÍ' if disp.get('is_disposable') else '✅ NO'}")
        
        return '\n'.join(out)

# ==========================================================
# DETECCIÓN DE TIPO
# ==========================================================
def detect_type(target):
    target = target.strip()
    
    if '@' in target and '.' in target.split('@')[1]:
        return 'email'
    if target.startswith('+') and len(target) >= 10 and target[1:].isdigit():
        return 'phone'
    if '.' in target and ' ' not in target:
        return 'domain'
    return 'username'

# ==========================================================
# CLASE PRINCIPAL
# ==========================================================
class LYRA:
    def __init__(self):
        self.phone = PhoneAnalyzer()
        self.email = EmailAnalyzer()
    
    def analyze(self, target):
        tipo = detect_type(target)
        if tipo == 'phone':
            return self.phone.analyze(target)
        elif tipo == 'email':
            return self.email.analyze(target)
        else:
            return {'error': f'Tipo no soportado: {tipo}'}

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
        print(f"""
{C.O}╔══════════════════════════════════════════════════════════════════╗
{C.O}║                                                                  ║
{C.O}║{C.G}       ██╗    ██╗   ██╗██████╗  █████╗               ║
{C.O}║{C.G}       ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗              ║
{C.O}║{C.G}       ██║     ╚████╔╝ ██████╔╝███████║              ║
{C.O}║{C.G}       ██║      ╚██╔╝  ██╔══██╗██╔══██║              ║
{C.O}║{C.G}       ███████╗  ██║   ██║  ██║██║  ██║              ║
{C.O}║{C.G}       ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝              ║
{C.O}║                                                                  ║
{C.O}║{C.C}                 ✧  L Y R A  P R O  ✧                   ║
{C.O}║{C.Y}           🔍 OSINT Ético y Funcional                  ║
{C.O}║{C.GR}                  ⚖️ Uso exclusivamente legal              ║
{C.O}║{C.G}         ✅ Sin WhatsApp - Sin Telegram - Sin logins      ║
{C.O}║                                                                  ║
{C.O}╚══════════════════════════════════════════════════════════════════╝{C.RST}
""")
    
    def menu(self):
        print(f"\n{C.C}╔══════════════════════════════════════════════════════════╗")
        print(f"{C.C}║                    M E N Ú   P R I N C I P A L            ║")
        print(f"{C.C}╚══════════════════════════════════════════════════════════╝{C.RST}")
        print(f"{C.O}[1]{C.RST} 📱 Análisis de Teléfono")
        print(f"{C.O}[2]{C.RST} 📧 Análisis de Email")
        print(f"{C.O}[0]{C.RST} 🚪 Salir")
    
    def phone_menu(self):
        self.clear()
        header("📱 ANÁLISIS DE TELÉFONO")
        number = input(f"{C.W}Número (ej. +34123456789): {C.RST}").strip()
        if not number:
            print(f"{C.R}Número inválido{C.RST}")
            input(f"{C.GR}Presiona Enter...{C.RST}")
            return
        print(f"\n{C.GR}Analizando...{C.RST}")
        results = self.lyra.analyze(number)
        if 'error' in results:
            print(f"{C.R}Error: {results['error']}{C.RST}")
        else:
            print(self.lyra.phone.format(results))
        input(f"\n{C.GR}Presiona Enter...{C.RST}")
    
    def email_menu(self):
        self.clear()
        header("📧 ANÁLISIS DE EMAIL")
        email = input(f"{C.W}Email: {C.RST}").strip()
        if not email or '@' not in email:
            print(f"{C.R}Email inválido{C.RST}")
            input(f"{C.GR}Presiona Enter...{C.RST}")
            return
        print(f"\n{C.GR}Analizando...{C.RST}")
        results = self.lyra.analyze(email)
        if 'error' in results:
            print(f"{C.R}Error: {results['error']}{C.RST}")
        else:
            print(self.lyra.email.format(results))
        input(f"\n{C.GR}Presiona Enter...{C.RST}")
    
    def run(self):
        while self.running:
            self.clear()
            self.banner()
            self.menu()
            opcion = input(f"\n{C.O}Elige una opción: {C.RST}").strip()
            if opcion == "1":
                self.phone_menu()
            elif opcion == "2":
                self.email_menu()
            elif opcion == "0":
                print(f"\n{C.G}👋 ¡Hasta luego!{C.RST}")
                self.running = False
            else:
                print(f"\n{C.R}Opción inválida{C.RST}")
                time.sleep(1)

# ==========================================================
# MAIN
# ==========================================================
def main():
    try:
        ui = LyraUI()
        ui.run()
    except KeyboardInterrupt:
        print(f"\n{C.Y}⚠️ Interrupción. ¡Hasta luego!{C.RST}")
    except Exception as e:
        print(f"\n{C.R}Error: {str(e)}{C.RST}")

if __name__ == '__main__':
    main()
