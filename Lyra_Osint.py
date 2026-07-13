#!/usr/bin/python
# ==========================================================
# LYRA PRO - Herramienta OSINT para investigadores profesionales
# Versión Ética Avanzada - Top Tier (CORREGIDA)
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
# COLORES MEJORADOS
# ==========================================================
class Colors:
    RED = '\033[1;31m'
    GREEN = '\033[1;32m'
    YELLOW = '\033[1;33m'
    ORANGE = '\033[38;5;208m'
    WHITE = '\033[1;37m'
    CYAN = '\033[1;36m'
    BLUE = '\033[1;34m'
    PURPLE = '\033[1;35m'
    GRAY = '\033[1;30m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN
    RESULT = WHITE
    HEADER = PURPLE

def cprint(text: str, color: str = Colors.WHITE, end: str = '\n'):
    print(f"{color}{text}{Colors.RESET}", end=end)

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
        'max_threads': 10,
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
# SISTEMA DE LOGGING MEJORADO
# ==========================================================
class Logger:
    def __init__(self, verbose: bool = False, log_file: str = None):
        self.verbose = verbose
        self.logs = []
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.DEBUG if verbose else logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            self.logger = logging.getLogger('LYRA')
        else:
            self.logger = None
    
    def log(self, message: str, level: str = 'INFO', color: str = Colors.WHITE):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.logs.append(log_entry)
        
        if self.verbose or level in ['ERROR', 'WARNING']:
            if level == 'ERROR':
                cprint(log_entry, Colors.ERROR)
            elif level == 'WARNING':
                cprint(log_entry, Colors.WARNING)
            elif level == 'SUCCESS':
                cprint(log_entry, Colors.SUCCESS)
            elif level == 'INFO':
                cprint(log_entry, Colors.INFO)
            else:
                cprint(log_entry, color)
        
        if self.logger:
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
        self.db_path = self.cache_dir / "cache.db"
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
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT value, timestamp, ttl FROM cache WHERE key = ?',
                (key,)
            )
            result = cursor.fetchone()
            conn.close()
            
            if result:
                value, timestamp, ttl = result
                if time.time() - timestamp < ttl:
                    return json.loads(value)
        except:
            pass
        return None
    
    def set(self, key: str, value: Any, ttl: int = 86400):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT OR REPLACE INTO cache (key, value, timestamp, ttl) VALUES (?, ?, ?, ?)',
                (key, json.dumps(value), int(time.time()), ttl)
            )
            conn.commit()
            conn.close()
        except:
            pass
    
    def clear(self):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM cache')
            conn.commit()
            conn.close()
        except:
            pass

# ==========================================================
# SISTEMA DE PROXY ROTATORIO
# ==========================================================
class ProxyRotator:
    def __init__(self, config: Dict):
        self.proxies = config.get('proxy', {}).get('list', [])
        self.enabled = config.get('proxy', {}).get('enabled', False)
        self.rotation = config.get('proxy', {}).get('rotation', 'round_robin')
        self.current_index = 0
        self.used_proxies = {}
    
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
    
    def mark_failed(self, proxy: str):
        if proxy in self.proxies:
            self.proxies.remove(proxy)

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
# MÓDULO DE EMAIL MEJORADO
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
                    method,
                    url,
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
                self.logger.debug(f"Error en intento {attempt + 1}: {str(e)}")
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
        
        hibp_result = self._check_hibp(email)
        if hibp_result:
            result['analysis']['breaches'] = hibp_result
        
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
        
        result = {'is_disposable': False, 'source': 'local', 'provider': None}
        
        disposable_domains = {
            'mailinator.com', 'guerrillamail.com', 'tempmail.com', '10minutemail.com',
            'throwawayemail.com', 'spamgourmet.com', 'spambox.us', 'trashmail.com',
            'yopmail.com', 'getnada.com', 'buzzbuzzbingo.com', 'fakeinbox.com',
            'ghostmail.com', 'maildrop.cc', 'mytemp.email', 'mailnator.com',
            'guerrillamail.org', 'guerrillamail.net', 'guerrillamail.biz',
            'mailmetrash.com', 'thankyou2010.com', 'trash2009.com', 'mt2009.com',
            'trashymail.com', 'tyldd.com', 'uggsrock.com', 'wegwerfmail.de',
            'wegwerfmail.net', 'wegwerfmail.org', 'wh4f.org', 'whyspam.me',
            'willselfdestruct.com', 'winemaven.info', 'wronghead.com', 'wuzup.net',
            'xagloo.com', 'xemaps.com', 'xents.com', 'xmaily.com', 'xoxy.net',
            'yep.it', 'yogamaven.com', 'yopmail.fr', 'yopmail.net', 'ypmail.webarnak.fr.eu.org'
        }
        
        if domain in disposable_domains:
            result['is_disposable'] = True
            result['source'] = 'local_list'
            result['provider'] = domain
        
        try:
            response = self._make_request(f"https://open.kickbox.com/v1/disposable/{domain}")
            if response and response.status_code == 200:
                data = response.json()
                if data.get('disposable', False):
                    result['is_disposable'] = True
                    result['source'] = 'kickbox_api'
                    result['provider'] = data.get('provider')
        except:
            pass
        
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
                result['records'].append({
                    'exchange': str(mx.exchange),
                    'preference': mx.preference
                })
            
            result['records'] = sorted(result['records'], key=lambda x: x['preference'])
        except dns.resolver.NXDOMAIN:
            result['valid'] = False
        except dns.resolver.NoAnswer:
            result['has_mx'] = False
        except Exception as e:
            self.logger.debug(f"Error MX para {domain}: {str(e)}")
            result['error'] = str(e)
        
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_smtp(self, email: str, domain: str) -> Dict:
        cache_key = f"smtp_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'valid': False,
            'status': 'unknown',
            'message': 'No se pudo verificar',
            'mail_server': None
        }
        
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
                    code, response = smtp.verify(email)
                    if code == 250:
                        result['valid'] = True
                        result['status'] = 'verified'
                        result['message'] = 'Email válido'
                        self.cache.set(cache_key, result, 3600)
                        return result
                except:
                    pass
                
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
                
        except (smtplib.SMTPException, socket.timeout, ConnectionRefusedError) as e:
            result['message'] = f'Error SMTP: {str(e)}'
        
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_hibp(self, email: str) -> Dict:
        cache_key = f"hibp_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'breaches': [], 'count': 0, 'pwned': False}
        
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            'User-Agent': 'LYRA-OSINT/2.0',
            'hibp-api-key': self.config['apis'].get('hibp', '')
        }
        
        try:
            response = self._make_request(url, headers=headers)
            
            if response and response.status_code == 200:
                data = response.json()
                result['pwned'] = True
                result['count'] = len(data)
                result['breaches'] = [
                    {
                        'name': b.get('Name', 'Desconocido'),
                        'date': b.get('BreachDate', 'Desconocida'),
                        'domain': b.get('Domain', 'Desconocido'),
                        'compromised_data': b.get('DataClasses', [])
                    }
                    for b in data
                ]
            elif response and response.status_code == 404:
                result['pwned'] = False
            elif response and response.status_code == 401:
                self.logger.warning("API key de HIBP inválida")
        except Exception as e:
            self.logger.debug(f"Error HIBP: {str(e)}")
        
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_reputation(self, email: str) -> Dict:
        cache_key = f"reputation_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'reputation': 'unknown',
            'score': 0,
            'is_spam': False,
            'is_risky': False,
            'details': {}
        }
        
        emailrep_url = self.config['apis'].get('emailrep', 'https://emailrep.io/')
        if emailrep_url:
            try:
                response = self._make_request(f"{emailrep_url}{email}")
                if response and response.status_code == 200:
                    data = response.json()
                    result['score'] = data.get('reputation', 0)
                    result['reputation'] = 'good' if data.get('suspicious', False) == False else 'bad'
                    result['is_spam'] = data.get('spam', False)
                    result['is_risky'] = data.get('suspicious', False)
                    result['details'] = {
                        'domain_rep': data.get('details', {}).get('domain_reputation', 0),
                        'smtp_rep': data.get('details', {}).get('smtp_reputation', 0),
                    }
            except Exception as e:
                self.logger.debug(f"Error EmailRep: {str(e)}")
        
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _find_linkedin(self, email: str) -> Dict:
        cache_key = f"linkedin_{email}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {'found': False, 'url': None, 'profile': None}
        
        search_patterns = [
            f"https://www.linkedin.com/search/results/people/?keywords={email}",
            f"https://www.linkedin.com/in/{email.split('@')[0]}",
            f"https://www.linkedin.com/pub/dir/{email.split('@')[0]}"
        ]
        
        for url in search_patterns:
            try:
                response = self._make_request(url)
                if response and response.status_code == 200:
                    html = response.text
                    profile_match = re.search(r'https://www.linkedin.com/in/[a-zA-Z0-9\-]+', html)
                    if profile_match:
                        result['found'] = True
                        result['url'] = profile_match.group(0)
                        break
            except:
                continue
        
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
                    result['commits'] = [
                        {
                            'repo': item['repository']['full_name'],
                            'message': item['commit']['message'][:100],
                            'date': item['commit']['author']['date'],
                            'url': item['html_url']
                        }
                        for item in data.get('items', [])[:5]
                    ]
        except Exception as e:
            self.logger.debug(f"Error GitHub: {str(e)}")
        
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
                    result['pastes'] = paste_links[:10]
        except:
            pass
        
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_spoofing(self, email: str, domain: str) -> Dict:
        result = {
            'risk_level': 'low',
            'has_dmarc': False,
            'has_spf': False,
            'has_dkim': False,
            'score': 0
        }
        
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
            
            score = 0
            if result['has_spf']: score += 1
            if result['has_dkim']: score += 1
            if result['has_dmarc']: score += 1
            
            result['score'] = score
            result['risk_level'] = 'high' if score < 2 else 'medium' if score == 2 else 'low'
            
        except Exception as e:
            self.logger.debug(f"Error en spoofing check: {str(e)}")
        
        return result
    
    def _calculate_confidence(self, analysis: Dict) -> Dict:
        score = 0
        max_score = 100
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
        elif breaches > 0:
            score -= min(breaches * 5, 20)
            details.append(f'{breaches} breaches found')
        
        spoofing = analysis.get('spoofing_risk', {})
        if spoofing.get('score', 0) >= 2:
            score += 10
            details.append('Good email security')
        
        score = max(0, min(score, max_score))
        
        return {
            'score': score,
            'level': 'high' if score >= 70 else 'medium' if score >= 40 else 'low',
            'details': details
        }
    
    def _analyze_metadata(self, email: str) -> Dict:
        result = {
            'pattern': 'standard',
            'format': 'unknown',
            'has_numbers': False,
            'length': len(email)
        }
        
        local_part = email.split('@')[0]
        
        if re.match(r'^[a-zA-Z]+\.[a-zA-Z]+$', local_part):
            result['pattern'] = 'first.last'
        elif re.match(r'^[a-zA-Z]+\.[a-zA-Z]+\d+$', local_part):
            result['pattern'] = 'first.last.number'
        elif re.match(r'^[a-zA-Z]+\d+$', local_part):
            result['pattern'] = 'name.number'
        elif re.match(r'^[a-zA-Z]+\d+[a-zA-Z]+$', local_part):
            result['pattern'] = 'name.number.letter'
        elif re.match(r'^[a-zA-Z]+$', local_part):
            result['pattern'] = 'only_first'
        
        result['has_numbers'] = bool(re.search(r'\d', local_part))
        result['format'] = 'professional' if '.' in local_part else 'personal'
        
        return result
    
    def format_results(self, results: Dict) -> str:
        if 'error' in results:
            return f"{Colors.ERROR}Error: {results['error']}{Colors.RESET}"
        
        output = []
        analysis = results.get('analysis', {})
        
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            📧  ANÁLISIS COMPLETO DE EMAIL                    ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        output.append(f"{Colors.INFO}Email: {Colors.RESULT}{results['email']}")
        output.append(f"{Colors.INFO}Dominio: {Colors.RESULT}{results['domain']}")
        
        disposable = analysis.get('disposable', {})
        output.append(f"\n{Colors.CYAN}📌 DOMINIO DESECHABLE:")
        if disposable.get('is_disposable'):
            output.append(f"{Colors.ERROR}  ⚠️ SÍ - Dominio desechable detectado")
            if disposable.get('provider'):
                output.append(f"{Colors.GRAY}    Proveedor: {disposable['provider']}")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ NO - Dominio legítimo")
        output.append(f"{Colors.GRAY}  Fuente: {disposable.get('source', 'desconocida')}")
        
        mx = analysis.get('mx_records', {})
        output.append(f"\n{Colors.CYAN}📌 SERVIDORES MX:")
        if mx.get('records'):
            for record in mx['records']:
                output.append(f"{Colors.RESULT}  📤 {record['exchange']} (Prioridad: {record['preference']})")
        else:
            output.append(f"{Colors.WARNING}  ⚠️ No se encontraron registros MX")
        
        smtp = analysis.get('smtp_verification', {})
        output.append(f"\n{Colors.CYAN}📌 VERIFICACIÓN SMTP:")
        if smtp.get('valid'):
            output.append(f"{Colors.SUCCESS}  ✅ Email válido")
        else:
            output.append(f"{Colors.WARNING}  ❓ No se pudo verificar")
        output.append(f"{Colors.GRAY}  {smtp.get('message', '')}")
        if smtp.get('mail_server'):
            output.append(f"{Colors.GRAY}  Servidor: {smtp['mail_server']}")
        
        rep = analysis.get('reputation', {})
        output.append(f"\n{Colors.CYAN}📌 REPUTACIÓN:")
        score = rep.get('score', 0)
        color = Colors.SUCCESS if score > 70 else Colors.WARNING if score > 30 else Colors.ERROR
        output.append(f"{Colors.RESULT}  Score: {color}{score}/100")
        if rep.get('is_spam'):
            output.append(f"{Colors.ERROR}  ⚠️ Reportado como spam")
        if rep.get('is_risky'):
            output.append(f"{Colors.ERROR}  ⚠️ Actividad sospechosa detectada")
        
        breaches = analysis.get('breaches', {})
        output.append(f"\n{Colors.CYAN}📌 FILTRACIONES:")
        if breaches.get('pwned'):
            output.append(f"{Colors.ERROR}  ⚠️ {breaches['count']} filtraciones encontradas")
            for breach in breaches.get('breaches', [])[:3]:
                output.append(f"{Colors.GRAY}    - {breach['name']} ({breach['date']})")
                if breach.get('compromised_data'):
                    output.append(f"{Colors.GRAY}      Datos: {', '.join(breach['compromised_data'][:3])}")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ No se encontraron filtraciones conocidas")
        
        linkedin = analysis.get('linkedin', {})
        output.append(f"\n{Colors.CYAN}📌 LINKEDIN:")
        if linkedin.get('found'):
            output.append(f"{Colors.SUCCESS}  ✅ Perfil encontrado")
            output.append(f"{Colors.RESULT}  {linkedin['url']}")
        else:
            output.append(f"{Colors.WARNING}  ❌ No se encontró perfil")
        
        github = analysis.get('github', {})
        output.append(f"\n{Colors.CYAN}📌 GITHUB:")
        if github.get('found'):
            output.append(f"{Colors.SUCCESS}  ✅ {github['count']} commits encontrados")
            for commit in github.get('commits', [])[:2]:
                output.append(f"{Colors.GRAY}    - {commit['repo']}: {commit['message'][:50]}...")
        else:
            output.append(f"{Colors.WARNING}  ❌ No se encontraron commits")
        
        spoofing = analysis.get('spoofing_risk', {})
        output.append(f"\n{Colors.CYAN}📌 SEGURIDAD EMAIL:")
        output.append(f"{Colors.RESULT}  SPF: {Colors.SUCCESS if spoofing.get('has_spf') else Colors.ERROR}{'✅' if spoofing.get('has_spf') else '❌'}")
        output.append(f"{Colors.RESULT}  DKIM: {Colors.SUCCESS if spoofing.get('has_dkim') else Colors.ERROR}{'✅' if spoofing.get('has_dkim') else '❌'}")
        output.append(f"{Colors.RESULT}  DMARC: {Colors.SUCCESS if spoofing.get('has_dmarc') else Colors.ERROR}{'✅' if spoofing.get('has_dmarc') else '❌'}")
        risk_level = spoofing.get('risk_level', 'low')
        risk_color = Colors.SUCCESS if risk_level == 'low' else Colors.WARNING if risk_level == 'medium' else Colors.ERROR
        output.append(f"{Colors.RESULT}  Riesgo: {risk_color}{risk_level.upper()}")
        
        confidence = analysis.get('confidence_score', {})
        output.append(f"\n{Colors.CYAN}📌 SCORE DE CONFIANZA:")
        score = confidence.get('score', 0)
        color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.ERROR
        output.append(f"{Colors.RESULT}  {color}{score}% - {confidence.get('level', 'unknown').upper()}")
        for detail in confidence.get('details', [])[:3]:
            output.append(f"{Colors.GRAY}    • {detail}")
        
        metadata = analysis.get('metadata', {})
        output.append(f"\n{Colors.CYAN}📌 METADATOS:")
        output.append(f"{Colors.RESULT}  Patrón: {metadata.get('pattern', 'unknown')}")
        output.append(f"{Colors.RESULT}  Formato: {metadata.get('format', 'unknown')}")
        output.append(f"{Colors.RESULT}  Longitud: {metadata['length']} caracteres")
        
        return '\n'.join(output)

# ==========================================================
# MÓDULO DE TELÉFONO (VERSIÓN SIMPLIFICADA)
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
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'es,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        
        for attempt in range(self.config['general']['max_retries']):
            try:
                proxy = self.proxy_rotator.get_proxy()
                timeout = self.config['general']['timeout']
                
                response = requests.get(
                    url,
                    headers={**self._get_headers(), **kwargs.get('headers', {})},
                    proxies=proxy,
                    timeout=timeout,
                    **{k: v for k, v in kwargs.items() if k != 'headers'}
                )
                
                if response.status_code == 429:
                    self.logger.warning(f"Rate limit en {url}")
                    time.sleep(2)
                    continue
                
                if response.status_code >= 500:
                    self.logger.warning(f"Error del servidor en {url}")
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
        result = {
            'number': number,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        self.logger.info(f"Analizando número: {number}")
        
        parsed_info = self._parse_phone(number)
        result['analysis']['parsed'] = parsed_info
        if not parsed_info.get('valid'):
            result['error'] = 'Número inválido'
            return result
        
        e164 = parsed_info['e164']
        
        result['analysis']['basic'] = {
            'country': parsed_info['country'],
            'operator': parsed_info['operator'],
            'location': parsed_info['location'],
            'type': parsed_info['type']
        }
        
        result['analysis']['geolocation'] = self._geo_locate(parsed_info)
        result['analysis']['risk_analysis'] = self._check_risk(e164)
        result['analysis']['spam_reputation'] = self._check_spam(e164)
        result['analysis']['platforms'] = self._check_platforms(e164)
        
        return result
    
    def _parse_phone(self, number: str) -> Dict:
        cache_key = f"parse_{number}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'valid': False,
            'e164': None,
            'national': None,
            'country': None,
            'operator': 'Desconocido',
            'location': 'No disponible',
            'type': 'Desconocido'
        }
        
        try:
            parsed = phonenumbers.parse(number, None)
            if phonenumbers.is_valid_number(parsed):
                result['valid'] = True
                result['e164'] = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
                result['national'] = str(parsed.national_number)
                result['country'] = phonenumbers.region_code_for_number(parsed)
                result['operator'] = carrier.name_for_number(parsed, "es") or 'Desconocido'
                result['location'] = geocoder.description_for_number(parsed, "es") or 'No disponible'
                
                type_map = {
                    phonenumbers.PhoneNumberType.FIXED_LINE: 'Fijo',
                    phonenumbers.PhoneNumberType.MOBILE: 'Móvil',
                    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: 'Fijo/Móvil',
                    phonenumbers.PhoneNumberType.TOLL_FREE: 'Gratuito',
                    phonenumbers.PhoneNumberType.PREMIUM_RATE: 'Premium',
                    phonenumbers.PhoneNumberType.SHARED_COST: 'Costo Compartido',
                    phonenumbers.PhoneNumberType.VOIP: 'VoIP',
                    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: 'Personal',
                    phonenumbers.PhoneNumberType.PAGER: 'Pager',
                    phonenumbers.PhoneNumberType.UAN: 'UAN',
                    phonenumbers.PhoneNumberType.VOICEMAIL: 'Voicemail',
                    phonenumbers.PhoneNumberType.UNKNOWN: 'Desconocido'
                }
                result['type'] = type_map.get(phonenumbers.number_type(parsed), 'Desconocido')
        
        except Exception as e:
            self.logger.debug(f"Error parseando número: {str(e)}")
        
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _geo_locate(self, parsed: Dict) -> Dict:
        result = {
            'latitude': None,
            'longitude': None,
            'location': parsed.get('location', ''),
            'country': parsed.get('country', ''),
            'accuracy': 'country'
        }
        
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
            country_coords = {
                'ES': {'lat': 40.416775, 'lon': -3.703790},
                'IT': {'lat': 41.9028, 'lon': 12.4964},
                'US': {'lat': 37.7749, 'lon': -122.4194},
                'UK': {'lat': 51.5074, 'lon': -0.1278},
                'FR': {'lat': 48.8566, 'lon': 2.3522},
                'DE': {'lat': 52.5200, 'lon': 13.4050},
                'MX': {'lat': 19.4326, 'lon': -99.1332},
                'AR': {'lat': -34.6037, 'lon': -58.3816},
                'CO': {'lat': 4.7110, 'lon': -74.0721},
                'CL': {'lat': -33.4489, 'lon': -70.6693},
                'PE': {'lat': -12.0464, 'lon': -77.0428},
                'VE': {'lat': 10.4806, 'lon': -66.9036},
            }
            if parsed['country'] in country_coords:
                coords = country_coords[parsed['country']]
                result['latitude'] = coords['lat']
                result['longitude'] = coords['lon']
                result['accuracy'] = 'country'
        
        return result
    
    def _check_risk(self, e164: str) -> Dict:
        cache_key = f"risk_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'is_voip': False,
            'risk_score': 0,
            'risk_level': 'low',
            'is_disposable': False,
            'is_fraudulent': False,
            'details': {}
        }
        
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
                        if score > 85:
                            result['risk_level'] = 'critical'
                        elif score > 65:
                            result['risk_level'] = 'high'
                        elif score > 40:
                            result['risk_level'] = 'medium'
                        else:
                            result['risk_level'] = 'low'
                        
                        result['details'] = {
                            'active': data.get('active', False),
                            'prepaid': data.get('prepaid', False),
                            'recent_activity': data.get('recent_abuse', False)
                        }
            except Exception as e:
                self.logger.debug(f"Error IPQS: {str(e)}")
        
        self.cache.set(cache_key, result, 3600)
        return result
    
    def _check_spam(self, e164: str) -> Dict:
        cache_key = f"spam_{e164}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'reported': False,
            'reports': 0,
            'last_report': None,
            'spam_score': 0
        }
        
        try:
            url = f"https://api.spamcalls.net/v1/phone/{e164}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                data = response.json()
                result['reported'] = data.get('reported', False)
                result['reports'] = data.get('reports', 0)
                if data.get('last_report'):
                    result['last_report'] = data['last_report']
        except Exception as e:
            self.logger.debug(f"Error spamcalls: {str(e)}")
        
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_platforms(self, e164: str) -> Dict:
        result = {
            'facebook': None,
            'twitter': None,
            'instagram': None,
            'google': None,
            'other': []
        }
        
        try:
            url = f"https://www.facebook.com/search/top/?q={e164}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                result['facebook'] = url
        except:
            pass
        
        try:
            url = f"https://twitter.com/search?q={e164}"
            response = self._make_request(url)
            if response and response.status_code == 200:
                result['twitter'] = url
        except:
            pass
        
        result['google'] = f"https://www.google.com/search?q={urllib.parse.quote(e164)}"
        
        clean = e164[1:]
        result['truecaller'] = f"https://www.truecaller.com/search/{clean}"
        
        return result
    
    def format_results(self, results: Dict) -> str:
        if 'error' in results:
            return f"{Colors.ERROR}Error: {results['error']}{Colors.RESET}"
        
        output = []
        analysis = results.get('analysis', {})
        
        output.append(f"\n{Colors.HEADER}╔═══════════════════════════════════════════════════════════════╗")
        output.append(f"{Colors.HEADER}║            📱  ANÁLISIS COMPLETO DE TELÉFONO                 ║")
        output.append(f"{Colors.HEADER}╚═══════════════════════════════════════════════════════════════╝")
        
        basic = analysis.get('basic', {})
        output.append(f"{Colors.INFO}Número: {Colors.RESULT}{results['number']}")
        output.append(f"{Colors.INFO}País: {Colors.RESULT}{basic.get('country', 'N/A')}")
        output.append(f"{Colors.INFO}Operador: {Colors.RESULT}{basic.get('operator', 'N/A')}")
        output.append(f"{Colors.INFO}Ubicación: {Colors.RESULT}{basic.get('location', 'N/A')}")
        output.append(f"{Colors.INFO}Tipo: {Colors.RESULT}{basic.get('type', 'N/A')}")
        
        geo = analysis.get('geolocation', {})
        if geo.get('latitude'):
            output.append(f"\n{Colors.CYAN}📍 UBICACIÓN:")
            output.append(f"{Colors.RESULT}  Coordenadas: {geo['latitude']}, {geo['longitude']}")
            output.append(f"{Colors.RESULT}  Precisión: {geo.get('accuracy', 'unknown')}")
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
            output.append(f"{Colors.ERROR}  ⚠️ Número desechable")
        if risk.get('is_fraudulent'):
            output.append(f"{Colors.ERROR}  ⚠️ Actividad fraudulenta")
        
        spam = analysis.get('spam_reputation', {})
        output.append(f"\n{Colors.CYAN}🚫 REPUTACIÓN SPAM:")
        if spam.get('reported'):
            output.append(f"{Colors.ERROR}  ⚠️ Reportado en spamcalls.net")
            output.append(f"{Colors.RESULT}  Reportes: {spam.get('reports', 0)}")
        else:
            output.append(f"{Colors.SUCCESS}  ✅ Sin reportes")
        if spam.get('spam_score', 0) > 0:
            output.append(f"{Colors.RESULT}  Score spam: {spam['spam_score']}/10")
        
        platforms = analysis.get('platforms', {})
        output.append(f"\n{Colors.CYAN}🔍 BÚSQUEDAS RÁPIDAS:")
        for name, url in platforms.items():
            if url:
                output.append(f"{Colors.RESULT}  {name}: {url}")
        
        return '\n'.join(output)

# ==========================================================
# MÓDULO DE DOMINIO (VERSIÓN SIMPLIFICADA)
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
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'application/json, text/html, */*',
            'Accept-Language': 'es,en;q=0.9'
        }
    
    def _make_request(self, url: str, **kwargs) -> Optional[requests.Response]:
        self.rate_limiter.wait()
        
        for attempt in range(self.config['general']['max_retries']):
            try:
                proxy = self.proxy_rotator.get_proxy()
                timeout = self.config['general']['timeout']
                
                response = requests.get(
                    url,
                    headers={**self._get_headers(), **kwargs.get('headers', {})},
                    proxies=proxy,
                    timeout=timeout,
                    **{k: v for k, v in kwargs.items() if k != 'headers'}
                )
                
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
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'analysis': {}
        }
        
        self.logger.info(f"Analizando dominio: {domain}")
        
        result['analysis']['whois'] = self._get_whois(domain)
        result['analysis']['dns'] = self._get_dns_records(domain)
        result['analysis']['ssl'] = self._get_ssl_info(domain)
        result['analysis']['security'] = self._check_security(domain)
        result['analysis']['risk_score'] = self._calculate_domain_risk(result['analysis'])
        
        return result
    
    def _get_whois(self, domain: str) -> Dict:
        cache_key = f"whois_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'registrant': None,
            'email': None,
            'country': None
        }
        
        try:
            w = whois.whois(domain)
            
            result['registrar'] = str(w.registrar) if w.registrar else None
            result['creation_date'] = str(w.creation_date[0]) if isinstance(w.creation_date, list) and w.creation_date else str(w.creation_date) if w.creation_date else None
            result['expiration_date'] = str(w.expiration_date[0]) if isinstance(w.expiration_date, list) and w.expiration_date else str(w.expiration_date) if w.expiration_date else None
            result['name_servers'] = w.name_servers if w.name_servers else []
            result['registrant'] = str(w.registrant) if w.registrant else None
            result['email'] = str(w.emails[0]) if w.emails and isinstance(w.emails, list) else str(w.emails) if w.emails else None
            result['country'] = str(w.country) if w.country else None
            
        except Exception as e:
            self.logger.debug(f"Error WHOIS: {str(e)}")
        
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _get_dns_records(self, domain: str) -> Dict:
        cache_key = f"dns_{domain}"
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'CNAME': [],
            'TXT': [],
            'NS': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'CNAME', 'TXT', 'NS']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type == 'MX':
                        result[record_type].append({
                            'exchange': str(rdata.exchange),
                            'preference': rdata.preference
                        })
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
        
        result = {
            'valid': False,
            'issuer': None,
            'subject': None,
            'expires': None,
            'valid_from': None,
            'san': []
        }
        
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
                        
        except Exception as e:
            self.logger.debug(f"Error SSL: {str(e)}")
        
        self.cache.set(cache_key, result, 86400)
        return result
    
    def _check_security(self, domain: str) -> Dict:
        result = {
            'headers': {},
            'issues': [],
            'score': 100
        }
        
        try:
            url = f"https://{domain}"
            response = self._make_request(url)
            
            if response and response.status_code == 200:
                headers = response.headers
                result['headers'] = dict(headers)
                
                checks = {
                    'Strict-Transport-Security': ('HSTS missing', 10),
                    'Content-Security-Policy': ('CSP missing', 15),
                    'X-Content-Type-Options': ('X-Content-Type-Options missing', 5),
                    'X-Frame-Options': ('X-Frame-Options missing', 5),
                    'Referrer-Policy': ('Referrer-Policy missing', 5),
                    'Permissions-Policy': ('Permissions-Policy missing', 5)
                }
                
                for header, (message, penalty) in checks.items():
                    if header not in headers:
                        result['issues'].append(message)
                        result['score'] -= penalty
                    
        except Exception as e:
            self.logger.debug(f"Error en security check: {str(e)}")
        
        result['score'] = max(0, result['score'])
        return result
    
    def _calculate_domain_risk(self, analysis: Dict) -> Dict:
        score = 100
        details = []
        
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
        
        score = max(0, min(100, score))
        
        return {
            'score': score,
            'level': 'low' if score >= 70 else 'medium' if score >= 40 else 'high',
            'details': details
        }
    
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
        
        security = analysis.get('security', {})
        output.append(f"\n{Colors.CYAN}🛡️ SEGURIDAD:")
        output.append(f"{Colors.RESULT}  Score: {security.get('score', 100)}/100")
        for issue in security.get('issues', []):
            output.append(f"{Colors.WARNING}  ⚠️ {issue}")
        
        risk = analysis.get('risk_score', {})
        score = risk.get('score', 100)
        color = Colors.SUCCESS if score >= 70 else Colors.WARNING if score >= 40 else Colors.ERROR
        output.append(f"\n{Colors.CYAN}⚠️ RIESGO:")
        output.append(f"{Colors.RESULT}  Score: {color}{score}/100 - {risk.get('level', 'unknown').upper()}")
        for detail in risk.get('details', [])[:3]:
            output.append(f"{Colors.GRAY}    • {detail}")
        
        return '\n'.join(output)

# ==========================================================
# SISTEMA DE EXPORTACIÓN DE RESULTADOS
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

# ==========================================================
# CLASE PRINCIPAL LYRA
# ==========================================================
class LYRA:
    def __init__(self, config_file: str = None):
        self.start_time = datetime.now()
        self.config = DEFAULT_CONFIG.copy()
        
        # Inicializar logger primero
        self.logger = Logger(False)
        
        # Cargar configuración
        self.load_config(config_file)
        
        # Actualizar logger con la configuración
        self.logger = Logger(self.config['general']['verbose'])
        
        # Inicializar caché
        self.cache = Cache()
        
        # Inicializar exportador
        self.exporter = ResultExporter(self.config['general']['output_dir'])
        
        # Inicializar analizadores
        self.email_analyzer = EmailAnalyzer(self.config, self.logger, self.cache)
        self.phone_analyzer = PhoneAnalyzer(self.config, self.logger, self.cache)
        self.domain_analyzer = DomainAnalyzer(self.config, self.logger, self.cache)
        
        self.logger.info(f"LYRA iniciada - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def load_config(self, config_file: str):
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        self.config.update(loaded_config)
            except Exception as e:
                self.logger.warning(f"Error cargando configuración: {str(e)}")
        else:
            if not Path(CONFIG_FILE).exists():
                try:
                    with open(CONFIG_FILE, 'w') as f:
                        yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
                    self.logger.info(f"Archivo de configuración creado: {CONFIG_FILE}")
                except Exception as e:
                    self.logger.warning(f"Error creando archivo de configuración: {str(e)}")
    
    def analyze(self, target: str, target_type: str = 'auto') -> Dict:
        if target_type == 'email' or ('@' in target and target_type == 'auto'):
            return self.email_analyzer.analyze_email(target)
        elif target_type == 'phone' or (target.startswith('+') and target_type == 'auto'):
            return self.phone_analyzer.analyze_phone(target)
        elif target_type == 'domain' or ('.' in target and ' ' not in target and target_type == 'auto'):
            return self.domain_analyzer.analyze_domain(target)
        else:
            return {'error': 'Tipo de target no reconocido'}
    
    def export_results(self, results: Dict, formats: List[str] = None, name: str = None) -> Dict:
        if not formats:
            formats = ['json']
        
        if not name:
            name = f"report_{self.exporter.timestamp}"
        
        exported = {}
        
        if 'json' in formats:
            exported['json'] = self.exporter.export_json(results, f"{name}.json")
        
        self.logger.success(f"Resultados exportados: {', '.join(exported.keys())}")
        return exported

# ==========================================================
# INTERFAZ DE USUARIO MEJORADA
# ==========================================================
class LyraUI:
    def __init__(self):
        self.lyra = LYRA()
        self.running = True
    
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def show_banner(self):
        banner = f"""
{Colors.ORANGE}╔══════════════════════════════════════════════════════════════════╗
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.GREEN}       ██╗    ██╗   ██╗██████╗  █████╗  ███████╗        {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗ ██╔══██╗       {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║     ╚████╔╝ ██████╔╝███████║ ███████║       {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ██║      ╚██╔╝  ██╔══██╗██╔══██║ ██╔══██║       {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ███████╗  ██║   ██║  ██║██║  ██║ ██║  ██║       {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GREEN}       ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═╝  ╚═╝       {Colors.ORANGE}║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.CYAN}                 ✧  L Y R A  P R O  ✧                   {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.YELLOW}           🔍 OSINT Ético para Investigadores            {Colors.ORANGE}║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}║{Colors.WHITE}                    Versión 2.0 - Top Tier                 {Colors.ORANGE}║
{Colors.ORANGE}║{Colors.GRAY}                  ⚖️ Uso exclusivamente legal              {Colors.ORANGE}║
{Colors.ORANGE}║                                                                  ║
{Colors.ORANGE}╚══════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
        print(banner)
    
    def show_menu(self):
        print(f"\n{Colors.CYAN}╔══════════════════════════════════════════════════════════╗")
        print(f"{Colors.CYAN}║                    M E N Ú   P R I N C I P A L            ║")
        print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════╝{Colors.RESET}")
        
        menu_options = [
            ("1", "📧 Análisis de Email", "Análisis completo de dirección email"),
            ("2", "📱 Análisis de Teléfono", "Análisis completo de número telefónico"),
            ("3", "🌐 Análisis de Dominio", "Análisis completo de dominio web"),
            ("4", "👤 Username Tracking", "Búsqueda en 300+ plataformas (próximamente)"),
            ("5", "🔍 Análisis Automático", "Detección automática del tipo de target"),
            ("6", "📊 Exportar Resultados", "Exportar resultados en JSON"),
            ("0", "🚪 Salir", "Salir de LYRA")
        ]
        
        for num, name, desc in menu_options:
            print(f"{Colors.ORANGE}[{num}]{Colors.RESET} {Colors.WHITE}{name}{Colors.RESET}")
            print(f"   {Colors.GRAY}{desc}{Colors.RESET}")
    
    def analyze_email_menu(self):
        self.clear()
        print(f"\n{Colors.CYAN}📧 ANÁLISIS DE EMAIL{Colors.RESET}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
        email = input(f"{Colors.WHITE}Email a analizar: {Colors.RESET}").strip()
        if not email or '@' not in email:
            print(f"{Colors.RED}Email inválido{Colors.RESET}")
            return
        
        print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
        results = self.lyra.email_analyzer.analyze_email(email)
        
        print(self.lyra.email_analyzer.format_results(results))
        
        export = input(f"\n{Colors.WHITE}¿Exportar resultados? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results({'email': results, 'target': email}, ['json'])
    
    def analyze_phone_menu(self):
        self.clear()
        print(f"\n{Colors.CYAN}📱 ANÁLISIS DE TELÉFONO{Colors.RESET}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
        number = input(f"{Colors.WHITE}Número (ej. +34123456789): {Colors.RESET}").strip()
        if not number:
            print(f"{Colors.RED}Número inválido{Colors.RESET}")
            return
        
        print(f"\n{Colors.GRAY}Analizando...{Colors.RESET}")
        results = self.lyra.phone_analyzer.analyze_phone(number)
        
        print(self.lyra.phone_analyzer.format_results(results))
        
        export = input(f"\n{Colors.WHITE}¿Exportar resultados? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results({'phone': results, 'target': number}, ['json'])
    
    def analyze_domain_menu(self):
        self.clear()
        print(f"\n{Colors.CYAN}🌐 ANÁLISIS DE DOMINIO{Colors.RESET}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
        domain = input(f"{Colors.WHITE}Dominio a analizar: {Colors.RESET}").strip()
        if not domain:
            print(f"{Colors.RED}Dominio inválido{Colors.RESET}")
            return
        
        print(f"\n{Colors.GRAY}Analizando... (puede tomar unos segundos){Colors.RESET}")
        results = self.lyra.domain_analyzer.analyze_domain(domain)
        
        print(self.lyra.domain_analyzer.format_results(results))
        
        export = input(f"\n{Colors.WHITE}¿Exportar resultados? (s/n): {Colors.RESET}").strip().lower()
        if export == 's':
            self.lyra.export_results({'domain': results, 'target': domain}, ['json'])
    
    def auto_analyze_menu(self):
        self.clear()
        print(f"\n{Colors.CYAN}🔍 ANÁLISIS AUTOMÁTICO{Colors.RESET}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
        target = input(f"{Colors.WHITE}Target (email, teléfono, dominio): {Colors.RESET}").strip()
        if not target:
            print(f"{Colors.RED}Target inválido{Colors.RESET}")
            return
        
        print(f"\n{Colors.GRAY}Detectando tipo...{Colors.RESET}")
        results = self.lyra.analyze(target, 'auto')
        
        if 'error' in results:
            print(f"{Colors.RED}Error: {results['error']}{Colors.RESET}")
            return
        
        if 'email' in results:
            print(self.lyra.email_analyzer.format_results(results))
        elif 'phone' in results:
            print(self.lyra.phone_analyzer.format_results(results))
        elif 'domain' in results:
            print(self.lyra.domain_analyzer.format_results(results))
        else:
            print(json.dumps(results, indent=2, ensure_ascii=False))
    
    def export_menu(self):
        self.clear()
        print(f"\n{Colors.CYAN}📊 EXPORTAR RESULTADOS{Colors.RESET}")
        print(f"{Colors.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}")
        
        output_dir = Path(self.lyra.config['general']['output_dir'])
        files = list(output_dir.glob("*.json"))
        
        if not files:
            print(f"{Colors.YELLOW}No hay resultados guardados{Colors.RESET}")
            return
        
        for i, file in enumerate(files, 1):
            size = file.stat().st_size / 1024
            print(f"{Colors.ORANGE}[{i}]{Colors.RESET} {file.name} ({size:.1f} KB)")
        
        choice = input(f"\n{Colors.WHITE}Selecciona archivo para ver (0 para cancelar): {Colors.RESET}").strip()
        if choice == '0':
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(files):
                file = files[idx]
                with open(file, 'r') as f:
                    data = json.load(f)
                    print(f"\n{Colors.CYAN}Contenido:{Colors.RESET}")
                    print(json.dumps(data, indent=2, ensure_ascii=False)[:2000] + "...")
        except:
            print(f"{Colors.RED}Error al leer archivo{Colors.RESET}")
    
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
                print(f"\n{Colors.YELLOW}🔜 Funcionalidad en desarrollo...{Colors.RESET}")
                time.sleep(1)
            elif choice == "5":
                self.auto_analyze_menu()
            elif choice == "6":
                self.export_menu()
            elif choice == "0":
                print(f"\n{Colors.GREEN}👋 ¡Gracias por usar LYRA!{Colors.RESET}")
                self.running = False
            else:
                print(f"\n{Colors.RED}Opción inválida{Colors.RESET}")
                time.sleep(1)

# ==========================================================
# PUNTO DE ENTRADA
# ==========================================================
def main():
    try:
        ui = LyraUI()
        ui.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}\n¡Hasta luego!{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}Error crítico: {str(e)}{Colors.RESET}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
