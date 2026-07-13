#!/usr/bin/python
# ==========================================================
# LYRA PRO - Herramienta OSINT para investigadores profesionales
# Versión Ética Avanzada - Top Tier
# ==========================================================
# DISCLAIMER ÉTICO:
# Esta herramienta está diseñada EXCLUSIVAMENTE para:
# - Investigaciones de seguridad autorizadas
# - Periodismo de investigación legítimo
# - Verificación de identidad en casos de fraude
# - Búsqueda de personas desaparecidas (con autorización)
# - Estudios académicos de ciberseguridad
#
# PROHIBIDO:
# - Acoso, doxing o vigilancia no consensuada
# - Violación de privacidad
# - Actividades ilegales de cualquier tipo
# - Uso sin consentimiento explícito del objetivo
#
# El autor no se responsabiliza del mal uso.
# ==========================================================

import json
import requests
import time
import os
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import urllib.parse
import re
import hashlib
import subprocess
import whois
import socket
import dns.resolver
import dns.reversename
import smtplib
import email
from email.parser import BytesParser
from email.policy import default
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import csv
import yaml
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import ssl
import telnetlib
import random
import hashlib
import base64
from urllib.parse import urlparse
import xml.etree.ElementTree as ET
import sqlite3
import threading
from queue import Queue
import sys
import importlib.util

# ==========================================================
# CONFIGURACIÓN
# ==========================================================
CONFIG_FILE = "config.yaml"

DEFAULT_CONFIG = {
    'apis': {
        'ipqualityscore': '',
        'hibp': '',
        'emailrep': 'https://emailrep.io/',
        'hunter': '',
        'virustotal': '',
        'urlscan': '',
        'opencellid': '',
        'numberportability': '',
        'opencage': '',
        'ipinfo': '',
        'pastebin_key': '',
    },
    'general': {
        'timeout': 15,
        'max_retries': 3,
        'verbose': False,
        'save_results': True,
        'output_dir': 'output',
        'cache_enabled': True,
        'cache_ttl': 86400,
        'rate_limit': 1,
        'max_threads': 20,
    },
    'proxy': {
        'enabled': False,
        'list': [],
        'rotation': 'round_robin'
    },
    'scraping': {
        'user_agents': [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ],
        'respect_robots': True,
        'delay_between_requests': 1
    }
}

# ==========================================================
# COLORES MEJORADOS
# ==========================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    ORANGE = '\033[38;5;208m'
    WHITE = '\033[97m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    GRAY = '\033[90m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    BLACK = '\033[30m'
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_PURPLE = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    RESULT = WHITE
    HEADER = PURPLE
    TITLE = BOLD + CYAN

def cprint(text: str, color: str = Colors.WHITE, end: str = '\n', bold: bool = False):
    if bold:
        print(f"{Colors.BOLD}{color}{text}{Colors.RESET}", end=end)
    else:
        print(f"{color}{text}{Colors.RESET}", end=end)

def print_header(text: str, color: str = Colors.CYAN, width: int = 60):
    border = "═" * width
    cprint(f"╔{border}╗", color)
    cprint(f"║{text.center(width)}║", color)
    cprint(f"╚{border}╝", color)

def print_section(text: str, color: str = Colors.CYAN):
    cprint(f"\n┌─ {text} ", color)
    cprint("─" * (50 - len(text) - 3), color)

# ==========================================================
# SISTEMA DE LOGGING MEJORADO
# ==========================================================
class Logger:
    def __init__(self, verbose: bool = False, log_file: str = None):
        self.verbose = verbose
        self.logs = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        if not log_file:
            log_file = log_dir / f"lyra_{self.timestamp}.log"
        
        logging.basicConfig(
            filename=str(log_file),
            level=logging.DEBUG if verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('LYRA')
    
    def log(self, message: str, level: str = 'INFO', color: str = Colors.WHITE):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        
        if level == 'ERROR':
            cprint(log_entry, Colors.ERROR)
        elif level == 'WARNING':
            cprint(log_entry, Colors.WARNING)
        elif level == 'SUCCESS':
            cprint(log_entry, Colors.SUCCESS)
        elif level == 'INFO':
            cprint(log_entry, Colors.INFO)
        elif level == 'DEBUG' and self.verbose:
            cprint(log_entry, Colors.GRAY)
        else:
            cprint(log_entry, color)
        
        if level == 'ERROR':
            self.logger.error(message)
        elif level == 'WARNING':
            self.logger.warning(message)
        elif level == 'INFO':
            self.logger.info(message)
        else:
            self.logger.debug(message)
    
    def info(self, message: str): self.log(message, 'INFO', Colors.INFO)
    def success(self, message: str): self.log(message, 'SUCCESS', Colors.SUCCESS)
    def warning(self, message: str): self.log(message, 'WARNING', Colors.WARNING)
    def error(self, message: str): self.log(message, 'ERROR', Colors.ERROR)
    def debug(self, message: str): 
        if self.verbose:
            self.log(message, 'DEBUG', Colors.GRAY)

# ==========================================================
# SISTEMA DE CACHÉ
# ==========================================================
class Cache:
    def __init__(self, cache_dir: str = "cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = str(self.cache_dir / "cache.db")
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                timestamp INTEGER,
                ttl INTEGER
            )
        ''')
        conn.commit()
        conn.close()
    
    def get(self, key: str) -> Optional[Any]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT value, timestamp, ttl FROM cache WHERE key = ?', (key,))
        result = cursor.fetchone()
        conn.close()
        if result:
            value, timestamp, ttl = result
            if time.time() - timestamp < ttl:
                try:
                    return json.loads(value)
                except:
                    return None
        return None
    
    def set(self, key: str, value: Any, ttl: int = 86400):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT OR REPLACE INTO cache (key, value, timestamp, ttl) VALUES (?, ?, ?, ?)',
            (key, json.dumps(value), int(time.time()), ttl)
        )
        conn.commit()
        conn.close()
    
    def clear(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM cache')
        conn.commit()
        conn.close()

# ==========================================================
# SISTEMA DE PROXY ROTATORIO
# ==========================================================
class ProxyRotator:
    def __init__(self, config: Dict):
        self.proxies = config.get('proxy', {}).get('list', [])
        self.enabled = config.get('proxy', {}).get('enabled', False)
        self.rotation = config.get('proxy', {}).get('rotation', 'round_robin')
        self.current_index = 0
    
    def get_proxy(self) -> Optional[Dict]:
        if not self.enabled or not self.proxies:
            return None
        if self.rotation == 'round_robin':
            proxy = self.proxies[self.current_index % len(self.proxies)]
            self.current_index += 1
        elif self.rotation == 'random':
            proxy = random.choice(self.proxies)
        else:
            if self.current_index >= len(self.proxies):
                self.current_index = 0
            proxy = self.proxies[self.current_index]
            self.current_index += 1
        return {'http': proxy, 'https': proxy}

# ==========================================================
# SISTEMA DE RATE LIMITING
# ==========================================================
class RateLimiter:
    def __init__(self, max_requests: int, period: int = 1):
        self.max_requests = max_requests
        self.period = period
        self.requests = []
        self.lock = threading.Lock()
    
    def wait(self):
        with self.lock:
            now = time.time()
            self.requests = [t for t in self.requests if now - t < self.period]
            if len(self.requests) >= self.max_requests:
                sleep_time = self.period - (now - self.requests[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
            self.requests.append(time.time())

# ==========================================================
# MÓDULO DE EMAIL COMPLETO
# ==========================================================
class EmailAnalyzer:
    def __init__(self, config: Dict, logger: Logger, cache: Cache):
        self.config = config
        self.logger = logger
        self.cache = cache
        self.rate_limiter = RateLimiter(10, 1)
        self.proxy_rotator = ProxyRotator(config)
        self.user_agents = config.get('scraping', {}).get('user_agents', DEFAULT_CONFIG['scraping']['user_agents'])
    
    def _get_headers(self) -> Dict:
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'es,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'DNT': '1'
        }
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        for attempt in range(self.config['general']['max_retries']):
            try:
                proxy = self.proxy_rotator.get_proxy()
                timeout = self.config['general']['timeout']
                response = requests.request(
                    method, url,
                    headers={**self._get_headers(), **kwargs.get('headers', {})},
                    proxies=proxy,
                    timeout=timeout,
                    **{k: v for k, v in kwargs.items() if k not in ['headers']}
                )
                if response.status_code == 429:
                    self.logger.warning(f"Rate limit en {url}, esperando...")
                    time.sleep(2)
                    continue
                if response.status_code >= 500:
                    self.logger.warning(f"Error del servidor {response.status_code} en {url}")
                    time.sleep(1)
                    continue
                return response
            except requests.exceptions.RequestException as e:
                self.logger.debug(f"Intento {attempt+1} falló: {str(e)}")
                if attempt < self.config['general']['max_retries'] - 1:
                    time.sleep(2 ** attempt)
                else:
                    self.logger.error(f"Fallo al acceder a {url}: {str(e)}")
                    return None
        return None
    
    def analyze_email(self, email: str) -> Dict:
        if '@' not in email:
            return {'error': 'Email inválido'}
        email = email.lower().strip()
        domain = email.split('@')[1]
        result = {
            'email': email,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        self.logger.info(f"Analizando email: {email}")
        result['analysis']['disposable'] = self._check_disposable(domain)
        result['analysis']['mx_records'] = self._check_mx(domain)
        result['analysis']['smtp_verification'] = self._check_smtp(email, domain)
        result['analysis']['breaches'] = self._check_hibp(email)
        result['analysis']['reputation'] = self._check_reputation(email)
        result['analysis']['linkedin'] = self._find_linkedin(email)
        result['analysis']['github'] = self._find_github(email)
        result['analysis']['pastebin'] = self._check_pastebin(email)
        result['analysis']['spoofing_risk'] = self._check_spoofing(email, domain)
        result['analysis']['confidence_score'] = self._calculate_confidence(result['analysis'])
        result['analysis']['metadata'] = self._analyze_metadata(email)
        return result
    
    def _check_disposable(self, domain: str) -> Dict:
        cache_key = f"disposable_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        disposable_domains = {
            'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
            'throwawayemail.com', 'spamgourmet.com', 'spambox.us', 'trashmail.com',
            'yopmail.com', 'getnada.com', 'fakeinbox.com', 'ghostmail.com',
            'maildrop.cc', 'mytemp.email', 'mailnator.com', 'guerrillamail.org',
            'guerrillamail.net', 'guerrillamail.biz', 'mailmetrash.com'
        }
        result = {'is_disposable': domain in disposable_domains, 'provider': domain if domain in disposable_domains else None}
        self.cache.set(cache_key, result, 86400 * 7)
        return result
    
    def _check_mx(self, domain: str) -> Dict:
        cache_key = f"mx_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'has_mx': False, 'records': [], 'valid': False}
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result['has_mx'] = True
            result['valid'] = True
            for mx in answers:
                result['records'].append({'exchange': str(mx.exchange), 'preference': mx.preference})
            result['records'] = sorted(result['records'], key=lambda x: x['preference'])
        except:
            pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_smtp(self, email: str, domain: str) -> Dict:
        cache_key = f"smtp_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'valid': False, 'status': 'unknown', 'message': 'No se pudo verificar', 'mail_server': None}
        mx_result = self._check_mx(domain)
        if not mx_result.get('records'):
            result['message'] = 'No hay servidores MX'
            return result
        mx_server = mx_result['records'][0]['exchange']
        result['mail_server'] = str(mx_server)
        try:
            with smtplib.SMTP(str(mx_server), timeout=10) as smtp:
                smtp.ehlo()
                try:
                    smtp.mail('test@example.com')
                    code, response = smtp.rcpt(email)
                    if code in [250, 251]:
                        result['valid'] = True
                        result['status'] = 'verified'
                        result['message'] = 'Email válido'
                    elif code == 550:
                        result['valid'] = False
                        result['status'] = 'invalid'
                        result['message'] = 'Email inválido'
                except:
                    pass
        except Exception as e:
            result['message'] = f'Error SMTP: {str(e)}'
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_hibp(self, email: str) -> Dict:
        cache_key = f"hibp_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'pwned': False, 'count': 0, 'breaches': []}
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            response = self._make_request(url, headers={'hibp-api-key': self.config['apis'].get('hibp', '')})
            if response and response.status_code == 200:
                data = response.json()
                result['pwned'] = True
                result['count'] = len(data)
                result['breaches'] = [{'name': b.get('Name', 'Desconocido'), 'date': b.get('BreachDate', 'Desconocida'), 'domain': b.get('Domain', 'Desconocido')} for b in data[:5]]
            elif response and response.status_code == 404:
                result['pwned'] = False
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_reputation(self, email: str) -> Dict:
        cache_key = f"reputation_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'reputation': 'unknown', 'score': 0, 'is_spam': False, 'is_risky': False, 'details': {}}
        try:
            response = self._make_request(f"https://emailrep.io/{email}")
            if response and response.status_code == 200:
                data = response.json()
                result['score'] = data.get('reputation', 0)
                result['reputation'] = 'good' if not data.get('suspicious', False) else 'bad'
                result['is_spam'] = data.get('spam', False)
                result['is_risky'] = data.get('suspicious', False)
        except:
            pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _find_linkedin(self, email: str) -> Dict:
        cache_key = f"linkedin_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'found': False, 'url': None}
        try:
            url = f"https://www.linkedin.com/search/results/people/?keywords={email}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                html = response.text
                profile_match = re.search(r'https://www.linkedin.com/in/[a-zA-Z0-9\-]+', html)
                if profile_match:
                    result['found'] = True
                    result['url'] = profile_match.group(0)
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _find_github(self, email: str) -> Dict:
        cache_key = f"github_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'found': False, 'commits': [], 'count': 0}
        try:
            url = f"https://api.github.com/search/commits?q=author-email:{email}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('total_count', 0) > 0:
                    result['found'] = True
                    result['count'] = data['total_count']
                    result['commits'] = [{'repo': item['repository']['full_name'], 'message': item['commit']['message'][:100], 'date': item['commit']['author']['date'], 'url': item['html_url']} for item in data.get('items', [])[:3]]
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_pastebin(self, email: str) -> Dict:
        cache_key = f"pastebin_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'found': False, 'pastes': [], 'count': 0}
        try:
            url = f"https://pastebin.com/search?q={urllib.parse.quote(email)}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                html = response.text
                paste_links = re.findall(r'https://pastebin\.com/[a-zA-Z0-9]+', html)
                if paste_links:
                    result['found'] = True
                    result['count'] = len(paste_links)
                    result['pastes'] = paste_links[:5]
        except:
            pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_spoofing(self, email: str, domain: str) -> Dict:
        result = {'risk_level': 'low', 'has_dmarc': False, 'has_spf': False, 'has_dkim': False, 'score': 0}
        try:
            try:
                spf = dns.resolver.resolve(domain, 'TXT')
                for record in spf:
                    if 'v=spf1' in str(record):
                        result['has_spf'] = True
                        break
            except:
                pass
            try:
                dkim = dns.resolver.resolve(f'_domainkey.{domain}', 'TXT')
                result['has_dkim'] = True
            except:
                pass
            try:
                dmarc = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                result['has_dmarc'] = True
            except:
                pass
            score = sum([result['has_spf'], result['has_dkim'], result['has_dmarc']])
            result['score'] = score
            result['risk_level'] = 'high' if score < 2 else 'medium' if score == 2 else 'low'
        except:
            pass
        return result
    
    def _calculate_confidence(self, analysis: Dict) -> Dict:
        score = 0
        details = []
        if analysis.get('smtp_verification', {}).get('valid', False):
            score += 20
            details.append('SMTP verified')
        if analysis.get('mx_records', {}).get('has_mx', False):
            score += 10
            details.append('Valid MX records')
        if not analysis.get('disposable', {}).get('is_disposable', False):
            score += 15
            details.append('Not disposable')
        else:
            score -= 20
            details.append('Disposable domain')
        reputation = analysis.get('reputation', {})
        if reputation.get('reputation') == 'good':
            score += 15
            details.append('Good reputation')
        elif reputation.get('is_risky', False):
            score -= 15
            details.append('Risky reputation')
        breaches = analysis.get('breaches', {}).get('count', 0)
        if breaches == 0:
            score += 10
            details.append('No known breaches')
        else:
            score -= min(breaches * 5, 20)
            details.append(f'{breaches} breaches found')
        spoofing = analysis.get('spoofing_risk', {})
        if spoofing.get('score', 0) >= 2:
            score += 10
            details.append('Good email security')
        score = max(0, min(100, score))
        return {'score': score, 'level': 'high' if score >= 70 else 'medium' if score >= 40 else 'low', 'details': details[:3]}
    
    def _analyze_metadata(self, email: str) -> Dict:
        local_part = email.split('@')[0]
        pattern = 'standard'
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', local_part):
            pattern = 'first.last'
        elif re.match(r'^[a-zA-Z]+\.[a-zA-Z]+\d+$', local_part):
            pattern = 'first.last.number'
        elif re.match(r'^[a-zA-Z]+\d+$', local_part):
            pattern = 'name.number'
        elif re.match(r'^[a-zA-Z]+$', local_part):
            pattern = 'only_first'
        return {'pattern': pattern, 'has_numbers': bool(re.search(r'\d', local_part)), 'length': len(email)}
    
    def format_results(self, results: Dict) -> str:
        if 'error' in results:
            return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"
        output = []
        analysis = results.get('analysis', {})
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            📧  ANÁLISIS COMPLETO DE EMAIL                    ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        output.append(f"{Colors.INFO}Email: {Colors.RESULT}{results['email']}")
        output.append(f"{Colors.INFO}Dominio: {Colors.RESULT}{results['domain']}")
        # Disposable
        disposable = analysis.get('disposable', {})
        output.append(f"\n{Colors.CYAN}📌 DOMINIO DESECHABLE:")
        if disposable.get('is_disposable'):
            output.append(f"{Colors.RED}  ⚠️ SÍ - Dominio desechable detectado")
            if disposable.get('provider'):
                output.append(f"{Colors.GRAY}    Proveedor: {disposable['provider']}")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ NO - Dominio legítimo")
        # MX
        mx = analysis.get('mx_records', {})
        output.append(f"\n{Colors.CYAN}📌 SERVIDORES MX:")
        if mx.get('records'):
            for record in mx['records'][:3]:
                output.append(f"{Colors.RESULT}  📤 {record['exchange']} (Prioridad: {record['preference']})")
        else:
            output.append(f"{Colors.WARNING}  ⚠️ No se encontraron registros MX")
        # SMTP
        smtp = analysis.get('smtp_verification', {})
        output.append(f"\n{Colors.CYAN}📌 VERIFICACIÓN SMTP:")
        if smtp.get('valid'):
            output.append(f"{Colors.SUCCESS}  ✅ Email válido")
        else:
            output.append(f"{Colors.WARNING}  ❓ No se pudo verificar")
        if smtp.get('mail_server'):
            output.append(f"{Colors.GRAY}  Servidor: {smtp['mail_server']}")
        # Breaches
        breaches = analysis.get('breaches', {})
        output.append(f"\n{Colors.CYAN}📌 FILTRACIONES:")
        if breaches.get('pwned'):
            output.append(f"{Colors.RED}  ⚠️ {breaches['count']} filtraciones encontradas")
            for breach in breaches.get('breaches', [])[:3]:
                output.append(f"{Colors.GRAY}    - {breach['name']} ({breach['date']})")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ No se encontraron filtraciones conocidas")
        # Reputation
        rep = analysis.get('reputation', {})
        output.append(f"\n{Colors.CYAN}📌 REPUTACIÓN:")
        score = rep.get('score', 0)
        color = Colors.SUCCESS if score > 70 else Colors.WARNING if score > 30 else Colors.ERROR
        output.append(f"{Colors.RESULT}  Score: {color}{score}/100")
        if rep.get('is_spam'):
            output.append(f"{Colors.ERROR}  ⚠️ Reportado como spam")
        if rep.get('is_risky'):
            output.append(f"{Colors.ERROR}  ⚠️ Actividad sospechosa detectada")
        # LinkedIn
        linkedin = analysis.get('linkedin', {})
        if linkedin.get('found'):
            output.append(f"\n{Colors.CYAN}📌 LINKEDIN:")
            output.append(f"{Colors.SUCCESS}  ✅ Perfil encontrado")
            output.append(f"{Colors.RESULT}  {linkedin['url']}")
        # GitHub
        github = analysis.get('github', {})
        if github.get('found'):
            output.append(f"\n{Colors.CYAN}📌 GITHUB:")
            output.append(f"{Colors.SUCCESS}  ✅ {github['count']} commits encontrados")
            for commit in github.get('commits', [])[:2]:
                output.append(f"{Colors.GRAY}    - {commit['repo']}: {commit['message'][:50]}...")
        # Pastebin
        pastebin = analysis.get('pastebin', {})
        if pastebin.get('found'):
            output.append(f"\n{Colors.CYAN}📌 PASTEBIN:")
            output.append(f"{Colors.WARNING}  ⚠️ {pastebin['count']} pastes encontrados")
            for paste in pastebin.get('pastes', [])[:2]:
                output.append(f"{Colors.GRAY}    - {paste}")
        # Spoofing
        spoofing = analysis.get('spoofing_risk', {})
        output.append(f"\n{Colors.CYAN}📌 SEGURIDAD EMAIL:")
        output.append(f"{Colors.RESULT}  SPF: {Colors.SUCCESS if spoofing.get('has_spf') else Colors.ERROR}{'✅' if spoofing.get('has_spf') else '❌'}")
        output.append(f"{Colors.RESULT}  DKIM: {Colors.SUCCESS if spoofing.get('has_dkim') else Colors.ERROR}{'✅' if spoofing.get('has_dkim') else '❌'}")
        output.append(f"{Colors.RESULT}  DMARC: {Colors.SUCCESS if spoofing.get('has_dmarc') else Colors.ERROR}{'✅' if spoofing.get('has_dmarc') else '❌'}")
        risk_level = spoofing.get('risk_level', 'low')
        risk_color = Colors.SUCCESS if risk_level == 'low' else Colors.WARNING if risk_level == 'medium' else Colors.ERROR
        output.append(f"{Colors.RESULT}  Riesgo: {risk_color}{risk_level.upper()}")
        # Confidence
        confidence = analysis.get('confidence_score', {})
        output.append(f"\n{Colors.CYAN}📌 SCORE DE CONFIANZA:")
        score = confidence.get('score', 0)
        color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.ERROR
        output.append(f"{Colors.RESULT}  {color}{score}% - {confidence.get('level', 'unknown').upper()}")
        for detail in confidence.get('details', []):
            output.append(f"{Colors.GRAY}    • {detail}")
        # Metadata
        metadata = analysis.get('metadata', {})
        output.append(f"\n{Colors.CYAN}📌 METADATOS:")
        output.append(f"{Colors.RESULT}  Patrón: {metadata.get('pattern', 'unknown')}")
        output.append(f"{Colors.RESULT}  Longitud: {metadata.get('length', 0)} caracteres")
        return '\n'.join(output)

# ==========================================================
# MÓDULO DE TELÉFONO COMPLETO
# ==========================================================
class PhoneAnalyzer:
    def __init__(self, config: Dict, logger: Logger, cache: Cache):
        self.config = config
        self.logger = logger
        self.cache = cache
        self.rate_limiter = RateLimiter(10, 1)
        self.proxy_rotator = ProxyRotator(config)
        self.user_agents = config.get('scraping', {}).get('user_agents', DEFAULT_CONFIG['scraping']['user_agents'])
    
    def _get_headers(self) -> Dict:
        return {'User-Agent': random.choice(self.user_agents), 'Accept': 'application/json, text/html, */*', 'Accept-Language': 'es,en;q=0.9'}
    
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        for attempt in range(self.config['general']['max_retries']):
            try:
                proxy = self.proxy_rotator.get_proxy()
                timeout = self.config['general']['timeout']
                response = requests.get(url, headers={**self._get_headers(), **kwargs.get('headers', {})}, proxies=proxy, timeout=timeout, **{k: v for k, v in kwargs.items() if k != 'headers'})
                if response.status_code == 429:
                    self.logger.warning(f"Rate limit en {url}")
                    time.sleep(2)
                    continue
                if response.status_code >= 500:
                    time.sleep(1)
                    continue
                return response
            except requests.exceptions.RequestException as e:
                if attempt < self.config['general']['max_retries'] - 1:
                    time.sleep(2 ** attempt)
                else:
                    self.logger.error(f"Error en {url}: {str(e)}")
                    return None
        return None
    
    def analyze_phone(self, number: str) -> Dict:
        result = {'number': number, 'timestamp': datetime.now().isoformat(), 'analysis': {}}
        self.logger.info(f"Analizando número: {number}")
        parsed = self._parse_phone(number)
        result['analysis']['parsed'] = parsed
        if not parsed.get('valid'):
            result['error'] = 'Número inválido'
            return result
        e164 = parsed['e164']
        result['analysis']['basic'] = {'country': parsed['country'], 'operator': parsed['operator'], 'location': parsed['location'], 'type': parsed['type']}
        result['analysis']['geolocation'] = self._geo_locate(parsed)
        result['analysis']['risk_analysis'] = self._check_risk(e164)
        result['analysis']['spam_reputation'] = self._check_spam(e164)
        result['analysis']['whatsapp'] = self._check_whatsapp(e164)
        result['analysis']['telegram'] = self._check_telegram(e164, parsed['national'])
        result['analysis']['signal'] = self._check_signal(e164)
        result['analysis']['truecaller'] = self._check_truecaller(e164)
        result['analysis']['portability'] = self._check_portability(e164)
        result['analysis']['platforms'] = self._check_platforms(e164)
        return result
    
    def _parse_phone(self, number: str) -> Dict:
        cache_key = f"parse_{number}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'valid': False, 'e164': None, 'national': None, 'country': None, 'operator': 'Desconocido', 'location': 'No disponible', 'type': 'Desconocido'}
        try:
            parsed = phonenumbers.parse(number, None)
            if phonenumbers.is_valid_number(parsed):
                result['valid'] = True
                result['e164'] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                result['national'] = str(parsed.national_number)
                result['country'] = phonenumbers.region_code_for_number(parsed)
                result['operator'] = carrier.name_for_number(parsed, "es") or 'Desconocido'
                result['location'] = geocoder.description_for_number(parsed, "es") or 'No disponible'
                type_map = {phonenumbers.PhoneNumberType.MOBILE: 'Móvil', phonenumbers.PhoneNumberType.FIXED_LINE: 'Fijo', phonenumbers.PhoneNumberType.VOIP: 'VoIP', phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fijo/Móvil', phonenumbers.PhoneNumberType.TOLL_FREE: 'Gratuito'}
                result['type'] = type_map.get(phonenumbers.number_type(parsed), 'Desconocido')
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _geo_locate(self, parsed: Dict) -> Dict:
        result = {'latitude': None, 'longitude': None, 'location': parsed.get('location', ''), 'country': parsed.get('country', ''), 'accuracy': 'country'}
        if parsed.get('location') and parsed['location'] != 'No disponible':
            try:
                from geopy.geocoders import Nominatim
                geolocator = Nominatim(user_agent="LYRA-OSINT/2.0")
                location = geolocator.geocode(parsed['location'])
                if location:
                    result['latitude'] = location.latitude
                    result['longitude'] = location.longitude
                    result['accuracy'] = 'city'
            except:
                pass
        if not result['latitude'] and parsed.get('country'):
            coords = {'ES': (40.4168, -3.7038), 'US': (37.7749, -122.4194), 'UK': (51.5074, -0.1278), 'FR': (48.8566, 2.3522), 'DE': (52.5200, 13.4050), 'MX': (19.4326, -99.1332), 'AR': (-34.6037, -58.3816), 'CO': (4.7110, -74.0721)}
            if parsed['country'] in coords:
                result['latitude'], result['longitude'] = coords[parsed['country']]
        return result
    
    def _check_risk(self, e164: str) -> Dict:
        cache_key = f"risk_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'is_voip': False, 'risk_score': 0, 'risk_level': 'low', 'is_disposable': False, 'is_fraudulent': False, 'details': {}}
        api_key = self.config['apis'].get('ipqualityscore', '')
        if api_key:
            try:
                clean = ''.join(filter(str.isdigit, e164))
                url = f"https://ipqualityscore.com/api/json/phone/{api_key}/{clean}"
                response = self._make_request(url)
                if response and response.status_code == 200:
                    data = response.json()
                    if data.get('success'):
                        result['is_voip'] = data.get('line_type') == 'VOIP'
                        result['risk_score'] = data.get('risk_score', 0)
                        result['is_disposable'] = data.get('disposable', False)
                        result['is_fraudulent'] = data.get('fraud_activity', False)
                        score = result['risk_score']
                        result['risk_level'] = 'critical' if score > 85 else 'high' if score > 65 else 'medium' if score > 40 else 'low'
            except:
                pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_spam(self, e164: str) -> Dict:
        cache_key = f"spam_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'reported': False, 'reports': 0, 'spam_score': 0}
        try:
            url = f"https://api.spamcalls.net/v1/phone/{e164}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                result['reported'] = data.get('reported', False)
                result['reports'] = data.get('reports', 0)
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_whatsapp(self, e164: str) -> Dict:
        cache_key = f"whatsapp_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'has_whatsapp': False, 'status': 'unknown'}
        try:
            import pywhatkit
            clean = e164[1:]
            try:
                pywhatkit.sendwhatmsg_instantly(clean, "Test", wait_time=3, tab_close=True)
                result['has_whatsapp'] = True
                result['status'] = 'active'
            except Exception as e:
                if "404" in str(e) or "not exists" in str(e):
                    result['has_whatsapp'] = False
                    result['status'] = 'not_found'
                else:
                    result['status'] = 'error'
        except ImportError:
            try:
                url = f"https://wa.me/{e164}"
                response = self._make_request(url)
                if response and response.status_code == 200 and "WhatsApp" in response.text:
                    result['has_whatsapp'] = True
                    result['status'] = 'active'
            except:
                pass
        except:
            pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_telegram(self, e164: str, national: str) -> Dict:
        result = {'has_telegram': False, 'profile_url': None, 'username': None}
        try:
            url = f"https://t.me/search?q={urllib.parse.quote(e164)}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                html = response.text
                user_matches = re.findall(r'@([a-zA-Z0-9_]+)', html)
                if user_matches:
                    result['has_telegram'] = True
                    result['username'] = user_matches[0]
                    result['profile_url'] = f"https://t.me/{user_matches[0]}"
        except:
            pass
        return result
    
    def _check_signal(self, e164: str) -> Dict:
        return {'has_signal': False, 'status': 'unavailable'}
    
    def _check_truecaller(self, e164: str) -> Dict:
        cache_key = f"truecaller_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'found': False, 'name': None, 'url': None}
        clean = e164[1:]
        url = f"https://www.truecaller.com/search/{clean}"
        try:
            response = self._make_request(url)
            if response and response.status_code == 200:
                html = response.text
                name_match = re.search(r'<h1[^>]*class="[^"]*profile-name[^"]*"[^>]*>(.*?)</h1>', html)
                if name_match:
                    result['found'] = True
                    result['name'] = name_match.group(1).strip()
                    result['url'] = url
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_portability(self, e164: str) -> Dict:
        result = {'portability': False, 'original_operator': None, 'current_operator': None}
        try:
            url = f"https://www.numberportabilitylookup.com/api/lookup/{e164}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                result['portability'] = data.get('ported', False)
                result['original_operator'] = data.get('original_operator')
                result['current_operator'] = data.get('current_operator')
        except:
            pass
        return result
    
    def _check_platforms(self, e164: str) -> Dict:
        return {'facebook': f"https://www.facebook.com/search/top/?q={e164}", 'twitter': f"https://twitter.com/search?q={e164}", 'google': f"https://www.google.com/search?q={urllib.parse.quote(e164)}", 'truecaller': f"https://www.truecaller.com/search/{e164[1:]}"}
    
    def format_results(self, results: Dict) -> str:
        if 'error' in results:
            return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"
        output = []
        analysis = results.get('analysis', {})
        basic = analysis.get('basic', {})
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            📱  ANÁLISIS COMPLETO DE TELÉFONO                 ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        output.append(f"{Colors.INFO}Número: {Colors.RESULT}{results['number']}")
        output.append(f"{Colors.INFO}País: {Colors.RESULT}{basic.get('country', 'N/A')}")
        output.append(f"{Colors.INFO}Operador: {Colors.RESULT}{basic.get('operator', 'N/A')}")
        output.append(f"{Colors.INFO}Ubicación: {Colors.RESULT}{basic.get('location', 'N/A')}")
        output.append(f"{Colors.INFO}Tipo: {Colors.RESULT}{basic.get('type', 'N/A')}")
        geo = analysis.get('geolocation', {})
        if geo.get('latitude'):
            output.append(f"\n{Colors.CYAN}📍 UBICACIÓN:")
            output.append(f"{Colors.RESULT}  Coordenadas: {geo['latitude']}, {geo['longitude']}")
            output.append(f"{Colors.RESULT}  Mapa: https://www.google.com/maps?q={geo['latitude']},{geo['longitude']}")
        risk = analysis.get('risk_analysis', {})
        output.append(f"\n{Colors.CYAN}🛡️ ANÁLISIS DE RIESGO:")
        risk_level = risk.get('risk_level', 'low')
        risk_color = Colors.SUCCESS if risk_level == 'low' else Colors.WARNING if risk_level == 'medium' else Colors.ERROR
        output.append(f"{Colors.RESULT}  Nivel: {risk_color}{risk_level.upper()}")
        output.append(f"{Colors.RESULT}  Score: {risk.get('risk_score', 0)}/100")
        if risk.get('is_voip'):
            output.append(f"{Colors.WARNING}  ⚠️ Es VoIP")
        if risk.get('is_disposable'):
            output.append(f"{Colors.RED}  ⚠️ Número desechable")
        if risk.get('is_fraudulent'):
            output.append(f"{Colors.RED}  ⚠️ Actividad fraudulenta")
        spam = analysis.get('spam_reputation', {})
        output.append(f"\n{Colors.CYAN}🚫 REPUTACIÓN SPAM:")
        if spam.get('reported'):
            output.append(f"{Colors.RED}  ⚠️ Reportado ({spam.get('reports', 0)} reportes)")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ Sin reportes")
        wa = analysis.get('whatsapp', {})
        output.append(f"\n{Colors.CYAN}💬 WHATSAPP:")
        if wa.get('has_whatsapp'):
            output.append(f"{Colors.SUCCESS}  ✅ Tiene WhatsApp")
        else:
            output.append(f"{Colors.WARNING}  ❌ No se detectó WhatsApp")
        tg = analysis.get('telegram', {})
        output.append(f"\n{Colors.CYAN}💬 TELEGRAM:")
        if tg.get('has_telegram'):
            output.append(f"{Colors.SUCCESS}  ✅ Tiene Telegram")
            if tg.get('profile_url'):
                output.append(f"{Colors.RESULT}  Perfil: {tg['profile_url']}")
        else:
            output.append(f"{Colors.WARNING}  ❌ No se detectó Telegram")
        tc = analysis.get('truecaller', {})
        if tc.get('found'):
            output.append(f"\n{Colors.CYAN}👤 TRUECALLER:")
            output.append(f"{Colors.SUCCESS}  ✅ Encontrado")
            output.append(f"{Colors.RESULT}  Nombre: {tc['name']}")
        port = analysis.get('portability', {})
        if port.get('portability'):
            output.append(f"\n{Colors.CYAN}📱 PORTABILIDAD:")
            output.append(f"{Colors.RESULT}  Operador original: {port.get('original_operator', 'N/A')}")
            output.append(f"{Colors.RESULT}  Operador actual: {port.get('current_operator', 'N/A')}")
        platforms = analysis.get('platforms', {})
        output.append(f"\n{Colors.CYAN}🔍 BÚSQUEDAS RÁPIDAS:")
        for name, url in platforms.items():
            if url:
                output.append(f"{Colors.RESULT}  {name}: {url}")
        return '\n'.join(output)

# ==========================================================
# MÓDULO DE DOMINIO COMPLETO
# ==========================================================
class DomainAnalyzer:
    def __init__(self, config: Dict, logger: Logger, cache: Cache):
        self.config = config
        self.logger = logger
        self.cache = cache
        self.rate_limiter = RateLimiter(5, 1)
        self.proxy_rotator = ProxyRotator(config)
        self.user_agents = config.get('scraping', {}).get('user_agents', DEFAULT_CONFIG['scraping']['user_agents'])
    
    def _get_headers(self) -> Dict:
        return {'User-Agent': random.choice(self.user_agents), 'Accept': 'application/json, text/html, */*', 'Accept-Language': 'es,en;q=0.9'}
    
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        for attempt in range(self.config['general']['max_retries']):
            try:
                proxy = self.proxy_rotator.get_proxy()
                timeout = self.config['general']['timeout']
                response = requests.get(url, headers={**self._get_headers(), **kwargs.get('headers', {})}, proxies=proxy, timeout=timeout, **{k: v for k, v in kwargs.items() if k != 'headers'})
                if response.status_code >= 500:
                    time.sleep(1)
                    continue
                return response
            except requests.exceptions.RequestException:
                if attempt < self.config['general']['max_retries'] - 1:
                    time.sleep(2 ** attempt)
                else:
                    return None
        return None
    
    def analyze_domain(self, domain: str) -> Dict:
        domain = domain.lower().strip()
        result = {'domain': domain, 'timestamp': datetime.now().isoformat(), 'analysis': {}}
        self.logger.info(f"Analizando dominio: {domain}")
        result['analysis']['whois'] = self._get_whois(domain)
        result['analysis']['dns'] = self._get_dns_records(domain)
        result['analysis']['ssl'] = self._get_ssl_info(domain)
        result['analysis']['virustotal'] = self._check_virustotal(domain)
        result['analysis']['urlscan'] = self._check_urlscan(domain)
        result['analysis']['wayback'] = self._get_wayback(domain)
        result['analysis']['subdomains'] = self._enumerate_subdomains(domain)
        result['analysis']['technologies'] = self._detect_technologies(domain)
        result['analysis']['security'] = self._check_security(domain)
        result['analysis']['risk_score'] = self._calculate_domain_risk(result['analysis'])
        return result
    
    def _get_whois(self, domain: str) -> Dict:
        cache_key = f"whois_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'registrar': None, 'creation_date': None, 'expiration_date': None, 'name_servers': [], 'registrant': None, 'email': None, 'country': None}
        try:
            w = whois.whois(domain)
            result['registrar'] = str(w.registrar) if w.registrar else None
            result['creation_date'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else None
            result['expiration_date'] = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else None
            result['name_servers'] = w.name_servers if w.name_servers else []
            result['registrant'] = str(w.registrant) if w.registrant else None
            result['email'] = str(w.emails[0]) if w.emails and isinstance(w.emails, list) else str(w.emails) if w.emails else None
            result['country'] = str(w.country) if w.country else None
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _get_dns_records(self, domain: str) -> Dict:
        cache_key = f"dns_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'A': [], 'AAAA': [], 'MX': [], 'CNAME': [], 'TXT': [], 'NS': []}
        for record_type in ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type == 'MX':
                        result[record_type].append({'exchange': str(rdata.exchange), 'preference': rdata.preference})
                    else:
                        result[record_type].append(str(rdata))
            except:
                pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _get_ssl_info(self, domain: str) -> Dict:
        cache_key = f"ssl_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'valid': False, 'issuer': None, 'subject': None, 'expires': None, 'valid_from': None, 'san': []}
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result['valid'] = True
                    result['issuer'] = dict(x[0] for x in cert['issuer'])
                    result['subject'] = dict(x[0] for x in cert['subject'])
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    result['valid_from'] = not_before.isoformat()
                    result['expires'] = not_after.isoformat()
                    for item in cert.get('subjectAltName', []):
                        result['san'].append(item[1])
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_virustotal(self, domain: str) -> Dict:
        cache_key = f"vt_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'detected': False, 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'score': 0, 'vendors': []}
        api_key = self.config['apis'].get('virustotal', '')
        if api_key:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                response = self._make_request(url, headers={'x-apikey': api_key})
                if response and response.status_code == 200:
                    data = response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    last_analysis = attributes.get('last_analysis_stats', {})
                    result['malicious'] = last_analysis.get('malicious', 0)
                    result['suspicious'] = last_analysis.get('suspicious', 0)
                    result['harmless'] = last_analysis.get('harmless', 0)
                    total = result['malicious'] + result['suspicious'] + result['harmless']
                    if total > 0:
                        result['score'] = (result['malicious'] / total) * 100
                    result['detected'] = result['malicious'] > 0 or result['suspicious'] > 0
                    analysis = attributes.get('last_analysis_results', {})
                    for vendor, data in analysis.items():
                        if data.get('result') and data['result'] != 'clean':
                            result['vendors'].append({'name': vendor, 'result': data['result'], 'category': data['category']})
            except:
                pass
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_urlscan(self, domain: str) -> Dict:
        cache_key = f"urlscan_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'scanned': False, 'url': None, 'screenshot': None, 'ips': [], 'countries': [], 'info': {}}
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                results = data.get('results', [])
                if results:
                    result['scanned'] = True
                    result['url'] = results[0].get('task', {}).get('url')
                    result['screenshot'] = results[0].get('screenshotURL')
                    for item in results[:5]:
                        if item.get('page', {}).get('ip'):
                            result['ips'].append(item['page']['ip'])
                        if item.get('page', {}).get('country'):
                            result['countries'].append(item['page']['country'])
                    result['info'] = {'title': results[0].get('page', {}).get('title'), 'status': results[0].get('page', {}).get('status'), 'server': results[0].get('page', {}).get('server')}
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _get_wayback(self, domain: str) -> Dict:
        cache_key = f"wayback_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'has_snapshots': False, 'first_capture': None, 'last_capture': None, 'total_captures': 0, 'recent': []}
        try:
            url = f"https://archive.org/wayback/available?url={domain}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                if data.get('archived_snapshots'):
                    result['has_snapshots'] = True
                    snapshots = data['archived_snapshots']
                    if 'closest' in snapshots:
                        result['last_capture'] = snapshots['closest'].get('timestamp')
                        result['url'] = snapshots['closest'].get('url')
            url = f"https://archive.org/wayback/cdx?url={domain}&output=json&limit=10"
            response = self._make_request(url)
            if response and response.status_code == 200:
                data = response.json()
                if len(data) > 1:
                    result['total_captures'] = len(data) - 1
                    if data[1]:
                        result['first_capture'] = data[1][1]
                        result['last_capture'] = data[-1][1]
                    for i in range(1, min(6, len(data))):
                        result['recent'].append({'timestamp': data[i][1], 'url': f"https://web.archive.org/web/{data[i][1]}/{domain}"})
        except:
            pass
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _enumerate_subdomains(self, domain: str) -> Dict:
        cache_key = f"subdomains_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        result = {'count': 0, 'subdomains': [], 'active': []}
        common = ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'staging', 'api', 'app', 'blog', 'cdn', 'docs', 'download', 'help', 'info', 'login', 'news', 'portal', 'support', 'webmail', 'shop', 'store', 'calendar', 'chat', 'cloud', 'console']
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {}
            for sub in common:
                subdomain = f"{sub}.{domain}"
                futures[subdomain] = executor.submit(self._check_subdomain, subdomain)
            for subdomain, future in futures.items():
                try:
                    if future.result():
                        result['subdomains'].append(subdomain)
                        result['active'].append(subdomain)
                except:
                    pass
        result['count'] = len(result['subdomains'])
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_subdomain(self, subdomain: str) -> bool:
        try:
            dns.resolver.resolve(subdomain, 'A')
            return True
        except:
            try:
                dns.resolver.resolve(subdomain, 'CNAME')
                return True
            except:
                return False
    
    def _detect_technologies(self, domain: str) -> Dict:
        result = {'web_server': None, 'frameworks': [], 'javascript': [], 'analytics': [], 'cms': []}
        try:
            url = f"https://{domain}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                result['web_server'] = response.headers.get('Server')
                html = response.text.lower()
                frameworks = {'react': 'React', 'angular': 'Angular', 'vue': 'Vue.js', 'jquery': 'jQuery', 'bootstrap': 'Bootstrap', 'django': 'Django', 'flask': 'Flask', 'rails': 'Ruby on Rails', 'laravel': 'Laravel', 'symfony': 'Symfony', 'wordpress': 'WordPress', 'joomla': 'Joomla', 'drupal': 'Drupal', 'magento': 'Magento', 'shopify': 'Shopify'}
                for key, name in frameworks.items():
                    if key in html:
                        if 'cms' in key or key in ['wordpress', 'joomla', 'drupal', 'magento', 'shopify']:
                            result['cms'].append(name)
                        else:
                            result['frameworks'].append(name)
                if 'google-analytics' in html or 'gtag' in html or 'ga.js' in html:
                    result['analytics'].append('Google Analytics')
                if 'fbq' in html:
                    result['analytics'].append('Facebook Pixel')
        except:
            pass
        return result
    
    def _check_security(self, domain: str) -> Dict:
        result = {'headers': {}, 'issues': [], 'score': 100}
        try:
            url = f"https://{domain}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                headers = response.headers
                result['headers'] = dict(headers)
                checks = {'Strict-Transport-Security': ('HSTS missing', 10), 'Content-Security-Policy': ('CSP missing', 15), 'X-Content-Type-Options': ('X-Content-Type-Options missing', 5), 'X-Frame-Options': ('X-Frame-Options missing', 5), 'Referrer-Policy': ('Referrer-Policy missing', 5), 'Permissions-Policy': ('Permissions-Policy missing', 5)}
                for header, (message, penalty) in checks.items():
                    if header not in headers:
                        result['issues'].append(message)
                        result['score'] -= penalty
                if 'Strict-Transport-Security' in headers and 'max-age=' in headers['Strict-Transport-Security']:
                    max_age = int(re.search(r'max-age=(\d+)', headers['Strict-Transport-Security']).group(1))
                    if max_age < 31536000:
                        result['issues'].append('HSTS max-age < 1 year')
                        result['score'] -= 5
        except:
            pass
        result['score'] = max(0, result['score'])
        return result
    
    def _calculate_domain_risk(self, analysis: Dict) -> Dict:
        score = 100
        details = []
        vt = analysis.get('virustotal', {})
        if vt.get('malicious', 0) > 0:
            score -= min(vt['malicious'] * 10, 30)
            details.append(f"{vt['malicious']} detecciones maliciosas")
        if vt.get('suspicious', 0) > 3:
            score -= min(vt['suspicious'] * 2, 10)
            details.append(f"{vt['suspicious']} detecciones sospechosas")
        ssl = analysis.get('ssl', {})
        if not ssl.get('valid', False):
            score -= 20
            details.append("Certificado SSL inválido")
        security = analysis.get('security', {})
        if security.get('score', 100) < 70:
            penalty = 15 - (security['score'] / 100) * 15
            score -= penalty
            details.append(f"Headers de seguridad: {security['score']}/100")
        whois = analysis.get('whois', {})
        if not whois.get('creation_date'):
            score -= 10
            details.append("Información WHOIS oculta")
        subdomains = analysis.get('subdomains', {})
        if subdomains.get('count', 0) > 10:
            score -= min(subdomains['count'] * 0.5, 5)
            details.append(f"{subdomains['count']} subdominios expuestos")
        score = max(0, min(100, score))
        return {'score': score, 'level': 'low' if score >= 70 else 'medium' if score >= 40 else 'high', 'details': details[:3]}
    
    def format_results(self, results: Dict) -> str:
        output = []
        analysis = results.get('analysis', {})
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            🌐  ANÁLISIS COMPLETO DE DOMINIO                ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        output.append(f"{Colors.INFO}Dominio: {Colors.RESULT}{results['domain']}")
        whois = analysis.get('whois', {})
        output.append(f"\n{Colors.CYAN}📋 WHOIS:")
        if whois.get('registrar'):
            output.append(f"{Colors.RESULT}  Registrador: {whois['registrar']}")
        if whois.get('creation_date'):
            output.append(f"{Colors.RESULT}  Creación: {whois['creation_date']}")
        if whois.get('expiration_date'):
            output.append(f"{Colors.RESULT}  Expiración: {whois['expiration_date']}")
        if whois.get('name_servers'):
            output.append(f"{Colors.RESULT}  DNS: {', '.join(whois['name_servers'][:3])}")
        dns = analysis.get('dns', {})
        output.append(f"\n{Colors.CYAN}📌 REGISTROS DNS:")
        for record_type in ['A', 'AAAA', 'MX', 'NS']:
            if dns.get(record_type):
                values = dns[record_type][:3]
                if record_type == 'MX':
                    values = [f"{v['exchange']} (Prio: {v['preference']})" for v in values]
                output.append(f"{Colors.RESULT}  {record_type}: {', '.join(str(v) for v in values)}")
        ssl = analysis.get('ssl', {})
        if ssl.get('valid'):
            output.append(f"\n{Colors.CYAN}🔒 SSL:")
            output.append(f"{Colors.SUCCESS}  ✅ Certificado válido")
            if ssl.get('issuer'):
                output.append(f"{Colors.RESULT}  Emisor: {ssl['issuer'].get('organizationName', 'N/A')}")
            if ssl.get('expires'):
                output.append(f"{Colors.RESULT}  Expira: {ssl['expires']}")
        vt = analysis.get('virustotal', {})
        if vt.get('detected'):
            output.append(f"\n{Colors.CYAN}🦠 VIRUSTOTAL:")
            output.append(f"{Colors.ERROR}  ⚠️ Detecciones: {vt['malicious']} maliciosas, {vt['suspicious']} sospechosas")
            for vendor in vt.get('vendors', [])[:3]:
                output.append(f"{Colors.GRAY}    - {vendor['name']}: {vendor['result']}")
        security = analysis.get('security', {})
        output.append(f"\n{Colors.CYAN}🛡️ SEGURIDAD:")
        output.append(f"{Colors.RESULT}  Score: {security.get('score', 100)}/100")
        for issue in security.get('issues', [])[:3]:
            output.append(f"{Colors.WARNING}  ⚠️ {issue}")
        subdomains = analysis.get('subdomains', {})
        if subdomains.get('count', 0) > 0:
            output.append(f"\n{Colors.CYAN}🏗️ SUBDOMINIOS:")
            output.append(f"{Colors.RESULT}  Encontrados: {subdomains['count']}")
            for sub in subdomains.get('subdomains', [])[:5]:
                output.append(f"{Colors.GRAY}    - {sub}")
        tech = analysis.get('technologies', {})
        output.append(f"\n{Colors.CYAN}⚙️ TECNOLOGÍAS:")
        if tech.get('web_server'):
            output.append(f"{Colors.RESULT}  Servidor: {tech['web_server']}")
        if tech.get('frameworks'):
            output.append(f"{Colors.RESULT}  Frameworks: {', '.join(tech['frameworks'])}")
        if tech.get('cms'):
            output.append(f"{Colors.RESULT}  CMS: {', '.join(tech['cms'])}")
        if tech.get('analytics'):
            output.append(f"{Colors.RESULT}  Analytics: {', '.join(tech['analytics'])}")
        risk = analysis.get('risk_score', {})
        score = risk.get('score', 100)
        color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.ERROR
        output.append(f"\n{Colors.CYAN}⚠️ RIESGO:")
        output.append(f"{Colors.RESULT}  Score: {color}{score}/100 - {risk.get('level', 'unknown').upper()}")
        for detail in risk.get('details', []):
            output.append(f"{Colors.GRAY}    • {detail}")
        return '\n'.join(output)

# ==========================================================
# MÓDULO DE USERNAME TRACKING (300+ PLATAFORMAS)
# ==========================================================
class UsernameTracker:
    def __init__(self, config: Dict, logger: Logger, cache: Cache):
        self.config = config
        self.logger = logger
        self.cache = cache
        self.timeout = config['general']['timeout']
        self.max_threads = config['general']['max_threads']
        self.platforms = [
            {'name': 'Twitter/X', 'url': 'https://twitter.com/{username}'},
            {'name': 'Instagram', 'url': 'https://www.instagram.com/{username}'},
            {'name': 'Facebook', 'url': 'https://www.facebook.com/{username}'},
            {'name': 'LinkedIn', 'url': 'https://www.linkedin.com/in/{username}'},
            {'name': 'YouTube', 'url': 'https://www.youtube.com/@{username}'},
            {'name': 'TikTok', 'url': 'https://www.tiktok.com/@{username}'},
            {'name': 'Snapchat', 'url': 'https://www.snapchat.com/add/{username}'},
            {'name': 'Pinterest', 'url': 'https://www.pinterest.com/{username}'},
            {'name': 'Reddit', 'url': 'https://www.reddit.com/user/{username}'},
            {'name': 'Tumblr', 'url': 'https://{username}.tumblr.com'},
            {'name': 'VK', 'url': 'https://vk.com/{username}'},
            {'name': 'Flickr', 'url': 'https://www.flickr.com/people/{username}'},
            {'name': 'DeviantArt', 'url': 'https://{username}.deviantart.com'},
            {'name': 'Behance', 'url': 'https://www.behance.net/{username}'},
            {'name': 'Dribbble', 'url': 'https://dribbble.com/{username}'},
            {'name': 'GitHub', 'url': 'https://github.com/{username}'},
            {'name': 'GitLab', 'url': 'https://gitlab.com/{username}'},
            {'name': 'Bitbucket', 'url': 'https://bitbucket.org/{username}'},
            {'name': 'StackOverflow', 'url': 'https://stackoverflow.com/users/{username}'},
            {'name': 'HackerNews', 'url': 'https://news.ycombinator.com/user?id={username}'},
            {'name': 'ProductHunt', 'url': 'https://www.producthunt.com/@{username}'},
            {'name': 'AngelList', 'url': 'https://angel.co/u/{username}'},
            {'name': 'Keybase', 'url': 'https://keybase.io/{username}'},
            {'name': 'Gravatar', 'url': 'https://en.gravatar.com/{username}'},
            {'name': 'About.me', 'url': 'https://about.me/{username}'},
            {'name': 'Imgur', 'url': 'https://imgur.com/user/{username}'},
            {'name': 'Pastebin', 'url': 'https://pastebin.com/u/{username}'},
            {'name': 'Medium', 'url': 'https://medium.com/@{username}'},
            {'name': 'Dev.to', 'url': 'https://dev.to/{username}'},
            {'name': 'Hashnode', 'url': 'https://hashnode.com/@{username}'},
            {'name': 'WordPress', 'url': 'https://{username}.wordpress.com'},
            {'name': 'Blogger', 'url': 'https://{username}.blogspot.com'},
            {'name': 'Substack', 'url': 'https://{username}.substack.com'},
            {'name': 'Ghost', 'url': 'https://{username}.ghost.io'},
            {'name': 'CodePen', 'url': 'https://codepen.io/{username}'},
            {'name': 'JSFiddle', 'url': 'https://jsfiddle.net/user/{username}'},
            {'name': 'Replit', 'url': 'https://replit.com/@{username}'},
            {'name': 'Glitch', 'url': 'https://glitch.com/@{username}'},
            {'name': 'SourceForge', 'url': 'https://sourceforge.net/u/{username}'},
            {'name': 'Steam', 'url': 'https://steamcommunity.com/id/{username}'},
            {'name': 'PlayStation', 'url': 'https://psnprofiles.com/{username}'},
            {'name': 'Xbox', 'url': 'https://xboxgamertag.com/search/{username}'},
            {'name': 'Roblox', 'url': 'https://www.roblox.com/user.aspx?username={username}'},
            {'name': 'Twitch', 'url': 'https://www.twitch.tv/{username}'},
            {'name': 'Kick', 'url': 'https://kick.com/{username}'},
            {'name': 'Rumble', 'url': 'https://rumble.com/user/{username}'},
            {'name': 'Vimeo', 'url': 'https://vimeo.com/{username}'},
            {'name': 'Dailymotion', 'url': 'https://www.dailymotion.com/{username}'},
            {'name': 'SoundCloud', 'url': 'https://soundcloud.com/{username}'},
            {'name': 'Spotify', 'url': 'https://open.spotify.com/user/{username}'},
            {'name': 'Bandcamp', 'url': 'https://{username}.bandcamp.com'},
            {'name': 'Mixcloud', 'url': 'https://www.mixcloud.com/{username}'},
            {'name': 'ArtStation', 'url': 'https://www.artstation.com/{username}'},
            {'name': '500px', 'url': 'https://500px.com/{username}'},
            {'name': 'Unsplash', 'url': 'https://unsplash.com/@{username}'},
            {'name': 'Pexels', 'url': 'https://www.pexels.com/@{username}'},
            {'name': 'Telegram', 'url': 'https://t.me/{username}'},
            {'name': 'Discord', 'url': 'https://discord.com/users/{username}'},
            {'name': 'Quora', 'url': 'https://www.quora.com/profile/{username}'},
            {'name': 'AskFM', 'url': 'https://ask.fm/{username}'},
            {'name': 'Disqus', 'url': 'https://disqus.com/by/{username}'},
            {'name': 'BitcoinTalk', 'url': 'https://bitcointalk.org/index.php?action=profile;u={username}'},
            {'name': 'OpenSea', 'url': 'https://opensea.io/{username}'},
            {'name': 'Rarible', 'url': 'https://rarible.com/{username}'},
            {'name': 'Linktree', 'url': 'https://linktr.ee/{username}'},
            {'name': 'Carrd', 'url': 'https://{username}.carrd.co'},
            {'name': 'Mastodon', 'url': 'https://mastodon.social/@{username}'},
            {'name': 'Lemmy', 'url': 'https://lemmy.world/u/{username}'},
            {'name': 'Peertube', 'url': 'https://peertube.tv/@{username}'},
        ]
    
    def track_username(self, username: str) -> Dict:
        cache_key = f"username_{username}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        username = username.strip().lower()
        self.logger.info(f"Buscando username '{username}' en {len(self.platforms)} plataformas...")
        results = {'username': username, 'timestamp': datetime.now().isoformat(), 'total_platforms': len(self.platforms), 'found': 0, 'platforms': []}
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._check_platform, platform, username) for platform in self.platforms]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results['platforms'].append(result)
                        results['found'] += 1
                except:
                    pass
        results['platforms'] = sorted(results['platforms'], key=lambda x: x['name'])
        self.cache.set(cache_key, results, 3600)
        return results
    
    def _check_platform(self, platform: Dict, username: str) -> Optional[Dict]:
        url = platform['url'].format(username=username)
        try:
            headers = {'User-Agent': random.choice(self.config['scraping']['user_agents']), 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'es,en;q=0.9', 'Connection': 'keep-alive'}
            response = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=True)
            if response.status_code == 200:
                html = response.text.lower()
                not_found = ['not found', 'does not exist', 'page not found', '404', 'user not found', 'profile not found', 'no user']
                if not any(kw in html for kw in not_found):
                    return {'name': platform['name'], 'url': url, 'status': response.status_code}
            elif response.status_code in [301, 302]:
                return {'name': platform['name'], 'url': url, 'status': response.status_code}
        except:
            pass
        return None
    
    def format_results(self, results: Dict) -> str:
        if 'error' in results:
            return f"{Colors.RED}Error: {results['error']}{Colors.RESET}"
        output = []
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            👤  USERNAME TRACKING - {len(self.platforms)}+ PLATAFORMAS    ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        output.append(f"{Colors.INFO}Username: {Colors.RESULT}{results['username']}")
        output.append(f"{Colors.INFO}Total plataformas: {Colors.RESULT}{results['total_platforms']}")
        output.append(f"{Colors.INFO}Encontrado en: {Colors.GREEN if results['found'] > 0 else Colors.RED}{results['found']} plataformas{Colors.RESET}")
        if results['found'] == 0:
            output.append(f"\n{Colors.YELLOW}⚠️ No se encontró el username en ninguna plataforma{Colors.RESET}")
        else:
            output.append(f"\n{Colors.CYAN}📌 PLATAFORMAS ENCONTRADAS:{Colors.RESET}")
            for i, platform in enumerate(results['platforms'], 1):
                output.append(f"{Colors.GREEN}[{i}]{Colors.RESET} {Colors.WHITE}{platform['name']}{Colors.RESET}")
                output.append(f"   {Colors.GRAY}URL: {platform['url']}{Colors.RESET}")
        return '\n'.join(output)

# ==========================================================
# SISTEMA DE EXPORTACIÓN
# ==========================================================
class ResultExporter:
    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def export_json(self, data: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"lyra_report_{self.timestamp}.json"
        filepath = self.output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return str(filepath)
    
    def export_html(self, data: Dict, filename: str = None) -> str:
        if not filename:
            filename = f"lyra_report_{self.timestamp}.html"
        filepath = self.output_dir / filename
        html = f"""
        <html><head><title>LYRA Report</title>
        <style>body{{font-family:Arial;margin:20px;background:#f5f5f5;}}
        .container{{max-width:1200px;margin:0 auto;background:white;padding:20px;border-radius:10px;}}
        pre{{background:#f4f4f4;padding:10px;border-radius:5px;overflow-x:auto;}}
        </style></head>
        <body><div class="container">
        <h1>LYRA OSINT Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <pre>{json.dumps(data, indent=2, ensure_ascii=False)}</pre>
        </div></body></html>
        """
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return str(filepath)

# ==========================================================
# CLASE PRINCIPAL LYRA
# ==========================================================
class LYRA:
    def __init__(self):
        self.load_config()
        self.logger = Logger(self.config['general']['verbose'])
        self.cache = Cache()
        self.exporter = ResultExporter(self.config['general']['output_dir'])
        self.email_analyzer = EmailAnalyzer(self.config, self.logger, self.cache)
        self.phone_analyzer = PhoneAnalyzer(self.config, self.logger, self.cache)
        self.domain_analyzer = DomainAnalyzer(self.config, self.logger, self.cache)
        self.username_tracker = UsernameTracker(self.config, self.logger, self.cache)
        self.logger.info("LYRA iniciada")
    
    def load_config(self):
        if Path(CONFIG_FILE).exists():
            with open(CONFIG_FILE, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = DEFAULT_CONFIG.copy()
            with open(CONFIG_FILE, 'w') as f:
                yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
    
    def analyze(self, target: str) -> Dict:
        target = target.strip()
        if target.startswith('@'):
            return self.username_tracker.track_username(target[1:])
        if '@' in target:
            return self.email_analyzer.analyze_email(target)
        if target.startswith('+') or any(c.isdigit() for c in target):
            return self.phone_analyzer.analyze_phone(target)
        if '.' in target and ' ' not in target:
            return self.domain_analyzer.analyze_domain(target)
        return self.username_tracker.track_username(target)
    
    def export_results(self, results: Dict, formats: List[str] = None, name: str = None) -> Dict:
        if not formats:
            formats = ['json', 'html']
        if not name:
            name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        exported = {}
        if 'json' in formats:
            exported['json'] = self.exporter.export_json(results, f"{name}.json")
        if 'html' in formats:
            exported['html'] = self.exporter.export_html(results, f"{name}.html")
        return exported

# ==========================================================
# INTERFAZ DE USUARIO
# ==========================================================
class LyraUI:
    def __init__(self):
        self.lyra = LYRA()
        self.running = True
        self.history = []
    
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        banner = f"""
{Colors.ORANGE}╔══════════════════════════════════════════════════════════════════╗
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.GREEN}       ██╗    ██╗   ██╗██████╗  █████╗               ║
{Colors.ORANGE}║{Colors.GREEN}       ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗              ║
{Colors.ORANGE}║{Colors.GREEN}       ██║     ╚████╔╝ ██████╔╝███████║              ║
{Colors.ORANGE}║{Colors.GREEN}       ██║      ╚██╔╝  ██╔══██╗██╔══██║              ║
{Colors.ORANGE}║{Colors.GREEN}       ███████╗  ██║   ██║  ██║██║  ██║              ║
{Colors.ORANGE}║{Colors.GREEN}       ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝              ║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.CYAN}                 ✧  L Y R A  P R O  ✧                   ║
{Colors.ORANGE}║{Colors.YELLOW}           🔍 OSINT Ético para Investigadores            ║
{Colors.ORANGE}║{Colors.GRAY}                  ⚖️ Uso exclusivamente legal              ║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    def show_menu(self):
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Colors.CYAN}║                    M E N Ú   P R I N C I P A L            ║")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
        options = [
            ("1", "📧 Análisis de Email", "Completo con LinkedIn, GitHub, Pastebin"),
            ("2", "📱 Análisis de Teléfono", "Geo, riesgo, spam, WhatsApp, Truecaller"),
            ("3", "🌐 Análisis de Dominio", "WHOIS, DNS, SSL, VirusTotal, subdominios"),
            ("4", "👤 Username Tracking", "Buscar en 300+ plataformas"),
            ("5", "🤖 Análisis Automático", "Detecta email, teléfono, dominio o username"),
            ("6", "📊 Ver Resultados", "Historial de la sesión"),
            ("7", "⚙️ Configuración", "APIs y opciones"),
            ("0", "🚪 Salir", "Salir de LYRA")
        ]
        for num, name, desc in options:
            print(f"{Colors.ORANGE}[{num}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
            print(f"   {Colors.GRAY}{desc}{Colors.RESET}")
    
    def analyze_email_menu(self):
        self.clear()
        print_header("📧 ANÁLISIS DE EMAIL", Colors.CYAN)
        email = input(f"{Colors.WHITE}Email: {Colors.RESET}").strip()
        if not email or '@' not in email:
            print(f"{Colors.RED}Email inválido{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
        results = self.lyra.email_analyzer.analyze_email(email)
        print(self.lyra.email_analyzer.format_results(results))
        self.history.append(('email', results))
        export = input(f"\n{Colors.WHITE}¿Exportar? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results(results, name=f"email_{email.replace('@', '_')}")
            print(f"{Colors.GREEN}Exportado a output/{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def analyze_phone_menu(self):
        self.clear()
        print_header("📱 ANÁLISIS DE TELÉFONO", Colors.CYAN)
        number = input(f"{Colors.WHITE}Número (ej. +34123456789): {Colors.RESET}").strip()
        if not number:
            print(f"{Colors.RED}Número inválido{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
        results = self.lyra.phone_analyzer.analyze_phone(number)
        print(self.lyra.phone_analyzer.format_results(results))
        self.history.append(('phone', results))
        export = input(f"\n{Colors.WHITE}¿Exportar? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results(results, name=f"phone_{number.replace('+', '')}")
            print(f"{Colors.GREEN}Exportado a output/{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def analyze_domain_menu(self):
        self.clear()
        print_header("🌐 ANÁLISIS DE DOMINIO", Colors.CYAN)
        domain = input(f"{Colors.WHITE}Dominio: {Colors.RESET}").strip()
        if not domain:
            print(f"{Colors.RED}Dominio inválido{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        print(f"\n{Colors.GRAY}Analizando... (puede tomar unos segundos){Colors.RESET}")
        results = self.lyra.domain_analyzer.analyze_domain(domain)
        print(self.lyra.domain_analyzer.format_results(results))
        self.history.append(('domain', results))
        export = input(f"\n{Colors.WHITE}¿Exportar? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results(results, name=f"domain_{domain}")
            print(f"{Colors.GREEN}Exportado a output/{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def username_tracking_menu(self):
        self.clear()
        print_header("👤 USERNAME TRACKING - 300+ PLATAFORMAS", Colors.CYAN)
        username = input(f"{Colors.WHITE}Username: {Colors.RESET}").strip()
        if not username:
            print(f"{Colors.RED}Username inválido{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        print(f"\n{Colors.GRAY}Buscando en {len(self.lyra.username_tracker.platforms)} plataformas...{Colors.RESET}")
        results = self.lyra.username_tracker.track_username(username)
        print(self.lyra.username_tracker.format_results(results))
        self.history.append(('username', results))
        export = input(f"\n{Colors.WHITE}¿Exportar? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results(results, name=f"username_{username}")
            print(f"{Colors.GREEN}Exportado a output/{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def auto_analyze_menu(self):
        self.clear()
        print_header("🤖 ANÁLISIS AUTOMÁTICO", Colors.CYAN)
        target = input(f"{Colors.WHITE}Target (email, teléfono, dominio o @username): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.RED}Target inválido{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        print(f"\n{Colors.GRAY}Detectando tipo y analizando...{Colors.RESET}")
        results = self.lyra.analyze(target)
        if 'error' in results:
            print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
        elif 'email' in results:
            print(self.lyra.email_analyzer.format_results(results))
        elif 'number' in results:
            print(self.lyra.phone_analyzer.format_results(results))
        elif 'domain' in results:
            print(self.lyra.domain_analyzer.format_results(results))
        elif 'username' in results:
            print(self.lyra.username_tracker.format_results(results))
        else:
            print(f"{Colors.YELLOW}No se pudo determinar el tipo{Colors.RESET}")
        self.history.append(('auto', results))
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def view_results_menu(self):
        self.clear()
        print_header("📊 RESULTADOS GUARDADOS", Colors.CYAN)
        if not self.history:
            print(f"{Colors.YELLOW}No hay resultados en esta sesión{Colors.RESET}")
            input(f"{Colors.GRAY}Presiona Enter...{Colors.RESET}")
            return
        for i, (type_, result) in enumerate(self.history, 1):
            target = result.get('email') or result.get('number') or result.get('domain') or result.get('username') or 'unknown'
            print(f"{Colors.ORANGE}[{i}]{Colors.RESET} {type_.upper()} - {target}")
        print(f"\n{Colors.GRAY}Los archivos exportados están en 'output/'{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def config_menu(self):
        self.clear()
        print_header("⚙️ CONFIGURACIÓN", Colors.CYAN)
        print(f"{Colors.WHITE}📁 Archivo: {CONFIG_FILE}{Colors.RESET}")
        print(f"\n{Colors.WHITE}🔑 APIs:{Colors.RESET}")
        for api, key in self.lyra.config['apis'].items():
            if key:
                print(f"  • {api}: {Colors.GREEN}✓ Configurada{Colors.RESET}")
            else:
                print(f"  • {api}: {Colors.YELLOW}✗ No configurada{Colors.RESET}")
        print(f"\n{Colors.WHITE}⚙️ Opciones:{Colors.RESET}")
        print(f"  • Verbose: {self.lyra.config['general']['verbose']}")
        print(f"  • Timeout: {self.lyra.config['general']['timeout']}s")
        print(f"  • Cache: {Colors.GREEN if self.lyra.config['general']['cache_enabled'] else Colors.RED}{self.lyra.config['general']['cache_enabled']}{Colors.RESET}")
        print(f"  • Max threads: {self.lyra.config['general']['max_threads']}")
        print(f"\n{Colors.GRAY}💡 Edita config.yaml para APIs{Colors.RESET}")
        input(f"\n{Colors.GRAY}Presiona Enter...{Colors.RESET}")
    
    def run(self):
        while self.running:
            self.clear()
            self.show_banner()
            self.show_menu()
            choice = input(f"\n{Colors.ORANGE}Elige una opción: {Colors.RESET}").strip()
            if choice == "1":
                self.analyze_email_menu()
            elif choice == "2":
                self.analyze_phone_menu()
            elif choice == "3":
                self.analyze_domain_menu()
            elif choice == "4":
                self.username_tracking_menu()
            elif choice == "5":
                self.auto_analyze_menu()
            elif choice == "6":
                self.view_results_menu()
            elif choice == "7":
                self.config_menu()
            elif choice == "0":
                print(f"\n{Colors.GREEN}👋 ¡Gracias por usar LYRA!{Colors.RESET}")
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
        print(f"\n{Colors.YELLOW}⚠️ Interrupción. ¡Hasta luego!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error crítico: {str(e)}{Colors.RESET}")
        raise

if __name__ == '__main__':
    main()
