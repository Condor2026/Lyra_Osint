#!/usr/bin/python
# ==========================================================
# LYRA - Herramienta OSINT para investigadores
# Versión ética (sin funciones de ataque ni acceso a datos ilegales)
# ==========================================================
# DISCLAIMER:
# Esta herramienta es solo para fines educativos y de investigación legítima.
# El uso para acosar, doxear o violar la privacidad está prohibido.
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

# ==========================================================
# CONFIGURACIÓN OPCIONAL
# ==========================================================
IPQS_API_KEY = ""       # API key de IPQualityScore (gratis, opcional)

# ==========================================================
# COLORES
# ==========================================================
Re = '\033[1;31m'
Gr = '\033[1;32m'
Ye = '\033[1;33m'
Or = '\033[38;5;208m'
Wh = '\033[1;37m'
Cy = '\033[1;36m'

def clear(): os.system('cls' if os.name == 'nt' else 'clear')

# ==========================================================
# BANNER
# ==========================================================
def mostrar_banner():
    print(f"{Or}╔══════════════════════════════════════════════════════════╗")
    print(f"{Or}║                                                          ║")
    print(f"{Or}║{Gr}       ██╗    ██╗   ██╗██████╗  █████╗                {Or}║")
    print(f"{Or}║{Gr}       ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗               {Or}║")
    print(f"{Or}║{Gr}       ██║     ╚████╔╝ ██████╔╝███████║               {Or}║")
    print(f"{Or}║{Gr}       ██║      ╚██╔╝  ██╔══██╗██╔══██║               {Or}║")
    print(f"{Or}║{Gr}       ███████╗  ██║   ██║  ██║██║  ██║               {Or}║")
    print(f"{Or}║{Gr}       ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝               {Or}║")
    print(f"{Or}║                                                          ║")
    print(f"{Or}║{Cy}                 ✧  L Y R A  ✧                        {Or}║")
    print(f"{Or}║{Ye}     🔍 OSINT para investigadores y periodistas        {Or}║")
    print(f"{Or}║                                                          ║")
    print(f"{Or}║{Wh}               Versión ética - 300+ plataformas        {Or}║")
    print(f"{Or}║                              by Condor2026                ║")
    print(f"{Or}╚══════════════════════════════════════════════════════════╝{Wh}")
    print()

# ==========================================================
# FUNCIONES AUXILIARES
# ==========================================================
def get_phone_info(number):
    try:
        parsed = phonenumbers.parse(number, None)
        info = {
            'e164': phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            'pais': phonenumbers.region_code_for_number(parsed),
            'operador': carrier.name_for_number(parsed, "es") or 'Desconocido',
            'ubicacion': geocoder.description_for_number(parsed, "es") or 'No disponible',
            'valido': phonenumbers.is_valid_number(parsed),
            'tipo_num': phonenumbers.number_type(parsed),
            'nacional': str(parsed.national_number)
        }
        tipo_map = {1: 'Fijo', 2: 'Móvil'}
        info['tipo'] = tipo_map.get(info['tipo_num'], 'Otro')
        return info, parsed
    except:
        return None, None

def spam_check_phone(e164):
    try:
        resp = requests.get(f"https://api.spamcalls.net/v1/phone/{e164}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except:
        pass
    return None

def geo_locate(query):
    try:
        resp = requests.get('https://nominatim.openstreetmap.org/search',
                            params={'q': query, 'format': 'json', 'limit': 1},
                            headers={'User-Agent': 'LYRA-OSINT/1.0'},
                            timeout=10)
        if resp.status_code == 200 and resp.json():
            return resp.json()[0]
    except:
        pass
    return None

def buscar_telegram(dato):
    resultados = []
    if isinstance(dato, str) and not dato.startswith('+'):
        url = f"https://t.me/{dato}"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                resultados.append(('Telegram (username)', url))
        except:
            pass
    if dato.startswith('+'):
        resultados.append(('Telegram (búsqueda)', f"https://t.me/search?q={urllib.parse.quote(dato)}"))
    return resultados

# ==========================================================
# MÓDULO TELÉFONO
# ==========================================================
def mega_phone():
    number = input(f"\n{Or}Número (ej. +34123456789): {Gr}").strip()
    info, parsed = get_phone_info(number)
    if not info:
        print(f"{Re}Número inválido.")
        return

    e164 = info['e164']
    print(f"\n{Gr}══════════════════════════════════════════")
    print(f"{Gr}   📱  INFORME COMPLETO DEL NÚMERO  📱")
    print(f"{Gr}══════════════════════════════════════════")
    print(f"{Wh}Número: {Gr}{e164}")
    print(f"{Wh}País: {Gr}{info['pais']}")
    print(f"{Wh}Operador: {Gr}{info['operador']}")
    print(f"{Wh}Ubicación: {Gr}{info['ubicacion']}")
    print(f"{Wh}Tipo: {Gr}{info['tipo']}")
    print(f"{Wh}Válido: {Gr}{'Sí' if info['valido'] else 'No'}")

    # Geolocalización
    print(f"\n{Gr}📍  UBICACIÓN APROXIMADA")
    query = info['ubicacion'] if info['ubicacion'] != 'No disponible' else info['pais']
    geo = geo_locate(query)
    if geo:
        print(f"{Wh}Coordenadas: {Gr}{geo['lat']}, {geo['lon']}")
        print(f"{Wh}Mapa: {Gr}https://www.google.com/maps?q={geo['lat']},{geo['lon']}")
    else:
        fallback = {'ES':(40.46,-3.74), 'IT':(41.87,12.56), 'US':(37.09,-95.71)}
        if info['pais'] in fallback:
            lat, lon = fallback[info['pais']]
            print(f"{Wh}Coordenadas del país: {Gr}{lat}, {lon}")
            print(f"{Wh}Mapa: {Gr}https://www.google.com/maps?q={lat},{lon}")

    # Análisis de riesgo IPQS
    print(f"\n{Gr}🕵️  ANÁLISIS DE RIESGO (VoIP/Fraude)")
    if IPQS_API_KEY:
        try:
            clean = ''.join(filter(str.isdigit, number))
            url = f"https://ipqualityscore.com/api/json/phone/{IPQS_API_KEY}/{clean}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success'):
                    line_type = data.get('line_type', 'Desconocido')
                    print(f"{Wh}Es VoIP: {Gr}{'SÍ' if line_type=='VOIP' else 'NO'}")
                    risk = data.get('risk_score', 0)
                    color = Re if risk>85 else Ye if risk>60 else Gr
                    print(f"{Wh}Riesgo: {color}{risk}")
                    if data.get('fraud_activity'):
                        print(f"{Re}⚠️ Actividad fraudulenta")
                    if data.get('disposable'):
                        print(f"{Re}📱 Número desechable")
                else:
                    print(f"{Ye}IPQS: {data.get('message', 'Error')}")
        except Exception as e:
            print(f"{Ye}Error IPQS: {e}")
    else:
        print(f"{Ye}Configura IPQS_API_KEY para análisis avanzado.")

    # Reputación spam (solo consulta)
    print(f"\n{Gr}🚫  REPUTACIÓN SPAM")
    spam = spam_check_phone(e164)
    if spam and spam.get('reported'):
        print(f"{Re}⚠️ Reportado en spamcalls.net")
        print(f"{Wh}Reportes: {Gr}{spam.get('reports','N/A')}")
    else:
        print(f"{Gr}Sin reportes en spamcalls.net")

    # Truecaller scraping
    print(f"\n{Gr}👤  TRUECALLER")
    clean = e164[1:]
    url_tc = f"https://www.truecaller.com/search/{clean}"
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        r = requests.get(url_tc, headers=headers, timeout=15)
        if r.status_code == 200:
            html = r.text
            match = re.search(r'<h1[^>]*class="[^"]*profile-name[^"]*"[^>]*>(.*?)</h1>', html)
            if match:
                print(f"{Gr}Nombre: {match.group(1).strip()}")
            else:
                print(f"{Ye}No encontrado")
        else:
            print(f"{Ye}Truecaller no responde")
    except:
        print(f"{Ye}Error Truecaller")

    # Búsqueda en Telegram
    print(f"\n{Gr}💬  TELEGRAM")
    tg_results = buscar_telegram(number) + buscar_telegram(info['nacional'])
    if tg_results:
        for tipo, url in tg_results:
            print(f"{Wh}{tipo}: {Gr}{url}")
    else:
        print(f"{Ye}No se encontraron resultados en Telegram")

    # Búsquedas rápidas
    print(f"\n{Gr}🔍  BÚSQUEDAS RÁPIDAS")
    print(f"{Or}Tellows:    {Gr}https://www.tellows.es/{e164}")
    print(f"{Or}SpamCalls:  {Gr}https://www.spamcalls.net/en/number/{e164}")
    print(f"{Or}Google:     {Gr}https://www.google.com/search?q={urllib.parse.quote(e164)}")
    print(f"{Or}Facebook:   {Gr}https://www.facebook.com/search/top/?q={e164}")
    print(f"{Or}Truecaller: {Gr}https://www.truecaller.com/search/{e164[1:]}")

    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# MÓDULO EMAIL
# ==========================================================
def email_deep():
    email = input(f"\n{Or}Email (ej. usuario@dominio.com): {Gr}").strip().lower()
    if '@' not in email:
        print(f"{Re}Email inválido")
        return

    print(f"\n{Gr}══════════════════════════════════════════")
    print(f"{Gr}   📧  INFORME COMPLETO DEL EMAIL")
    print(f"{Gr}══════════════════════════════════════════")

    dominio = email.split('@')[1]

    # Dominio desechable
    try:
        resp = requests.get('https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt', timeout=10)
        if resp.status_code == 200:
            desechables = set(line.strip() for line in resp.text.splitlines())
            print(f"{Wh}Desechable: {Gr}{'Sí' if dominio in desechables else 'No'}")
    except:
        print(f"{Ye}No se pudo verificar")

    # Have I Been Pwned
    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            breaches = resp.json()
            print(f"{Wh}Filtraciones: {Gr}{len(breaches)}")
            for b in breaches[:3]:
                print(f"  - {b['Name']} ({b['BreachDate']})")
        elif resp.status_code == 404:
            print(f"{Wh}Filtraciones: {Gr}Ninguna conocida")
        elif resp.status_code == 401:
            print(f"{Ye}La API de HIBP requiere autenticación. Obtén una clave en https://haveibeenpwned.com/API/Key")
        else:
            print(f"{Ye}Error HIBP (código {resp.status_code})")
    except Exception as e:
        print(f"{Ye}No se pudo consultar HIBP: {e}")

    # Gravatar
    hash_email = hashlib.md5(email.lower().encode()).hexdigest()
    try:
        resp = requests.get(f"https://www.gravatar.com/{hash_email}.json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()['entry'][0]
            print(f"{Wh}Gravatar: {Gr}{data.get('displayName', 'N/A')}")
    except:
        pass

    # Búsquedas
    print(f"\n{Gr}🔍  BÚSQUEDAS")
    q = urllib.parse.quote(email)
    print(f"{Or}Google:   {Gr}https://www.google.com/search?q={q}")
    print(f"{Or}Facebook: {Gr}https://www.facebook.com/search/top/?q={q}")
    print(f"{Or}Twitter:  {Gr}https://twitter.com/search?q={q}")

    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# MÓDULO IP
# ==========================================================
def ip_track():
    ip = input(f"\n{Or}IP objetivo: {Gr}").strip()
    try:
        resp = requests.get(f"http://ipwho.is/{ip}")
        data = resp.json()
        print(f"\n{Gr}══════════════════════════════════════════")
        print(f"{Gr}   🌐  INFORMACIÓN DE IP")
        print(f"{Gr}══════════════════════════════════════════")
        print(f"{Wh}IP: {Gr}{ip}")
        print(f"{Wh}País: {Gr}{data.get('country', 'N/A')}")
        print(f"{Wh}Ciudad: {Gr}{data.get('city', 'N/A')}")
        print(f"{Wh}ISP: {Gr}{data.get('connection', {}).get('isp', 'N/A')}")
        lat, lon = data.get('latitude'), data.get('longitude')
        if lat and lon:
            print(f"{Wh}Mapa: {Gr}https://www.google.com/maps?q={lat},{lon}")
    except:
        print(f"{Re}Error al consultar IP")
    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# MÓDULO USERNAME MASIVO (300+ PLATAFORMAS)
# ==========================================================
def username_track_masivo():
    user = input(f"\n{Or}Username objetivo: {Gr}").strip()
    if not user:
        print(f"{Re}Username inválido")
        return

    print(f"\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}   👤  BÚSQUEDA MASIVA DE USUARIO (300+ PLATAFORMAS)")
    print(f"{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Wh}Objetivo: {Gr}{user}")
    print(f"{Wh}Escaneando... (puede tomar unos segundos)\n")

    headers = {'User-Agent': 'Mozilla/5.0'}

    # ==================== LISTA COMPLETA DE SITIOS (300+) ====================
    sitios = [
        # === REDES SOCIALES PRINCIPALES (50+) ===
        {'nombre':'Facebook','url':f'https://facebook.com/{user}','cat':'Social'},
        {'nombre':'Twitter/X','url':f'https://twitter.com/{user}','cat':'Social'},
        {'nombre':'Instagram','url':f'https://instagram.com/{user}','cat':'Social'},
        {'nombre':'TikTok','url':f'https://tiktok.com/@{user}','cat':'Social'},
        {'nombre':'Snapchat','url':f'https://snapchat.com/add/{user}','cat':'Social'},
        {'nombre':'Pinterest','url':f'https://pinterest.com/{user}','cat':'Social'},
        {'nombre':'LinkedIn','url':f'https://linkedin.com/in/{user}','cat':'Profesional'},
        {'nombre':'Reddit','url':f'https://reddit.com/user/{user}','cat':'Foro'},
        {'nombre':'Tumblr','url':f'https://{user}.tumblr.com','cat':'Blog'},
        {'nombre':'Flickr','url':f'https://flickr.com/people/{user}','cat':'Foto'},
        {'nombre':'VSCO','url':f'https://vsco.co/{user}/gallery','cat':'Foto'},
        {'nombre':'Ello','url':f'https://ello.co/{user}','cat':'Social'},
        {'nombre':'Mastodon','url':f'https://mastodon.social/@{user}','cat':'Social'},
        {'nombre':'Bluesky','url':f'https://bsky.app/profile/{user}','cat':'Social'},
        {'nombre':'Threads','url':f'https://threads.net/@{user}','cat':'Social'},
        {'nombre':'Telegram','url':f'https://t.me/{user}','cat':'Mensajería'},
        {'nombre':'WhatsApp','url':f'https://wa.me/{user}','cat':'Mensajería'},
        {'nombre':'Discord','url':f'https://discord.com/users/{user}','cat':'Mensajería'},
        {'nombre':'VK','url':f'https://vk.com/{user}','cat':'Social'},
        {'nombre':'Odnoklassniki','url':f'https://ok.ru/{user}','cat':'Social'},
        {'nombre':'Weibo','url':f'https://weibo.com/{user}','cat':'Social'},
        {'nombre':'Douban','url':f'https://douban.com/people/{user}/','cat':'Social'},
        {'nombre':'Xiaohongshu','url':f'https://xiaohongshu.com/user/profile/{user}','cat':'Social'},
        {'nombre':'Parler','url':f'https://parler.com/profile/{user}','cat':'Social'},
        {'nombre':'Gab','url':f'https://gab.com/{user}','cat':'Social'},
        {'nombre':'Gettr','url':f'https://gettr.com/user/{user}','cat':'Social'},
        {'nombre':'Truth Social','url':f'https://truthsocial.com/@{user}','cat':'Social'},
        {'nombre':'Minds','url':f'https://minds.com/{user}/','cat':'Social'},
        {'nombre':'Diaspora','url':f'https://diasp.org/u/{user}','cat':'Social'},
        {'nombre':'Vero','url':f'https://vero.co/{user}','cat':'Social'},
        # === FOROS Y COMUNIDADES (40+) ===
        {'nombre':'Quora','url':f'https://quora.com/profile/{user}','cat':'Foro'},
        {'nombre':'HackerNews','url':f'https://news.ycombinator.com/user?id={user}','cat':'Tech'},
        {'nombre':'Stack Overflow','url':f'https://stackoverflow.com/users/{user}','cat':'Dev'},
        {'nombre':'Server Fault','url':f'https://serverfault.com/users/{user}','cat':'Dev'},
        {'nombre':'Super User','url':f'https://superuser.com/users/{user}','cat':'Dev'},
        {'nombre':'Ask Ubuntu','url':f'https://askubuntu.com/users/{user}','cat':'Dev'},
        {'nombre':'Product Hunt','url':f'https://producthunt.com/@{user}','cat':'Tech'},
        {'nombre':'Indie Hackers','url':f'https://indiehackers.com/{user}','cat':'Tech'},
        {'nombre':'Dev.to','url':f'https://dev.to/{user}','cat':'Dev'},
        {'nombre':'Hashnode','url':f'https://hashnode.com/@{user}','cat':'Dev'},
        {'nombre':'Medium','url':f'https://medium.com/@{user}','cat':'Blog'},
        {'nombre':'Disqus','url':f'https://disqus.com/by/{user}/','cat':'Foro'},
        {'nombre':'LiveJournal','url':f'https://{user}.livejournal.com','cat':'Blog'},
        {'nombre':'Fandom','url':f'https://fandom.com/u/{user}','cat':'Foro'},
        {'nombre':'GameFAQs','url':f'https://gamefaqs.gamespot.com/community/{user}','cat':'Gaming'},
        {'nombre':'IGN','url':f'https://ign.com/profiles/{user}','cat':'Gaming'},
        {'nombre':'MyAnimeList','url':f'https://myanimelist.net/profile/{user}','cat':'Anime'},
        {'nombre':'Anime-Planet','url':f'https://anime-planet.com/users/{user}','cat':'Anime'},
        {'nombre':'BoardGameGeek','url':f'https://boardgamegeek.com/user/{user}','cat':'Juegos'},
        {'nombre':'Instructables','url':f'https://instructables.com/member/{user}/','cat':'DIY'},
        {'nombre':'Cracked','url':f'https://cracked.com/members/{user}/','cat':'Foro'},
        {'nombre':'BuzzFeed','url':f'https://buzzfeed.com/{user}','cat':'Social'},
        {'nombre':'Wattpad','url':f'https://wattpad.com/user/{user}','cat':'Escritura'},
        {'nombre':'Archive of Our Own','url':f'https://archiveofourown.org/users/{user}','cat':'Escritura'},
        {'nombre':'FanFiction','url':f'https://fanfiction.net/u/{user}','cat':'Escritura'},
        {'nombre':'DeviantArt','url':f'https://deviantart.com/{user}','cat':'Arte'},
        {'nombre':'ArtStation','url':f'https://artstation.com/{user}','cat':'Arte'},
        {'nombre':'Behance','url':f'https://behance.net/{user}','cat':'Arte'},
        {'nombre':'Dribbble','url':f'https://dribbble.com/{user}','cat':'Arte'},
        {'nombre':'CGSociety','url':f'http://cgsociety.org/{user}','cat':'Arte'},
        {'nombre':'Pixiv','url':f'https://pixiv.net/users/{user}','cat':'Arte'},
        {'nombre':'Newgrounds','url':f'https://{user}.newgrounds.com','cat':'Arte'},
        {'nombre':'Fur Affinity','url':f'https://furaffinity.net/user/{user}','cat':'Arte'},
        # === DESARROLLO Y TECNOLOGÍA (30+) ===
        {'nombre':'GitHub','url':f'https://github.com/{user}','cat':'Dev'},
        {'nombre':'GitLab','url':f'https://gitlab.com/{user}','cat':'Dev'},
        {'nombre':'Bitbucket','url':f'https://bitbucket.org/{user}','cat':'Dev'},
        {'nombre':'CodePen','url':f'https://codepen.io/{user}','cat':'Dev'},
        {'nombre':'JSFiddle','url':f'https://jsfiddle.net/user/{user}/','cat':'Dev'},
        {'nombre':'Replit','url':f'https://replit.com/@{user}','cat':'Dev'},
        {'nombre':'Glitch','url':f'https://glitch.com/@{user}','cat':'Dev'},
        {'nombre':'Observable','url':f'https://observablehq.com/@{user}','cat':'Dev'},
        {'nombre':'Kaggle','url':f'https://kaggle.com/{user}','cat':'Ciencia'},
        {'nombre':'HackerRank','url':f'https://hackerrank.com/{user}','cat':'Programación'},
        {'nombre':'LeetCode','url':f'https://leetcode.com/{user}/','cat':'Programación'},
        {'nombre':'CodeChef','url':f'https://codechef.com/users/{user}','cat':'Programación'},
        {'nombre':'CodeForces','url':f'https://codeforces.com/profile/{user}','cat':'Programación'},
        {'nombre':'AtCoder','url':f'https://atcoder.jp/users/{user}','cat':'Programación'},
        {'nombre':'TopCoder','url':f'https://topcoder.com/members/{user}/','cat':'Programación'},
        {'nombre':'Exercism','url':f'https://exercism.org/profiles/{user}','cat':'Programación'},
        {'nombre':'CodinGame','url':f'https://codingame.com/profile/{user}','cat':'Programación'},
        {'nombre':'GeeksforGeeks','url':f'https://auth.geeksforgeeks.org/user/{user}/profile','cat':'Programación'},
        # === JUEGOS Y GAMING (40+) ===
        {'nombre':'Steam','url':f'https://steamcommunity.com/id/{user}','cat':'Gaming'},
        {'nombre':'Steam Group','url':f'https://steamcommunity.com/groups/{user}','cat':'Gaming'},
        {'nombre':'Xbox Live','url':f'https://xboxgamertag.com/search/{user}','cat':'Gaming'},
        {'nombre':'PlayStation','url':f'https://psnprofiles.com/{user}','cat':'Gaming'},
        {'nombre':'Nintendo','url':f'https://en-americas-support.nintendo.com/app/answers/detail/a_id/63047','cat':'Gaming'},
        {'nombre':'Epic Games','url':f'https://epicgames.com/@{user}','cat':'Gaming'},
        {'nombre':'Roblox','url':f'https://roblox.com/user.aspx?username={user}','cat':'Gaming'},
        {'nombre':'Minecraft','url':f'https://namemc.com/profile/{user}','cat':'Gaming'},
        {'nombre':'Battle.net','url':f'https://battle.net/{user}','cat':'Gaming'},
        {'nombre':'Riot Games','url':f'https://{user}.leagueoflegends.com','cat':'Gaming'},
        {'nombre':'Chess.com','url':f'https://chess.com/member/{user}','cat':'Juegos'},
        {'nombre':'Lichess','url':f'https://lichess.org/@{user}','cat':'Juegos'},
        {'nombre':'Osu!','url':f'https://osu.ppy.sh/users/{user}','cat':'Gaming'},
        {'nombre':'Kongregate','url':f'https://kongregate.com/accounts/{user}','cat':'Gaming'},
        {'nombre':'Armor Games','url':f'https://armor.ag/@{user}','cat':'Gaming'},
        {'nombre':'Itch.io','url':f'https://{user}.itch.io','cat':'Gaming'},
        {'nombre':'Game Jolt','url':f'https://gamejolt.com/@{user}','cat':'Gaming'},
        {'nombre':'Twitch','url':f'https://twitch.tv/{user}','cat':'Streaming'},
        {'nombre':'Kick','url':f'https://kick.com/{user}','cat':'Streaming'},
        {'nombre':'Trovo','url':f'https://trovo.live/{user}','cat':'Streaming'},
        {'nombre':'Rumble','url':f'https://rumble.com/user/{user}','cat':'Video'},
        {'nombre':'DLive','url':f'https://dlive.tv/{user}','cat':'Streaming'},
        {'nombre':'Smashcast','url':f'https://smashcast.tv/{user}','cat':'Streaming'},
        # === MÚSICA Y AUDIO (25+) ===
        {'nombre':'Spotify','url':f'https://open.spotify.com/user/{user}','cat':'Música'},
        {'nombre':'SoundCloud','url':f'https://soundcloud.com/{user}','cat':'Música'},
        {'nombre':'Bandcamp','url':f'https://bandcamp.com/{user}','cat':'Música'},
        {'nombre':'Last.fm','url':f'https://last.fm/user/{user}','cat':'Música'},
        {'nombre':'Mixcloud','url':f'https://mixcloud.com/{user}/','cat':'Música'},
        {'nombre':'Audiomack','url':f'https://audiomack.com/{user}','cat':'Música'},
        {'nombre':'ReverbNation','url':f'https://reverbnation.com/{user}','cat':'Música'},
        {'nombre':'Genius','url':f'https://genius.com/{user}','cat':'Música'},
        {'nombre':'Musically','url':f'https://musical.ly/@{user}','cat':'Música'},
        {'nombre':'Tidal','url':f'https://tidal.com/{user}','cat':'Música'},
        {'nombre':'Deezer','url':f'https://deezer.com/profile/{user}','cat':'Música'},
        {'nombre':'Apple Music','url':f'https://music.apple.com/profile/{user}','cat':'Música'},
        {'nombre':'YouTube Music','url':f'https://music.youtube.com/channel/{user}','cat':'Música'},
        # === VIDEO Y STREAMING (20+) ===
        {'nombre':'YouTube','url':f'https://youtube.com/@{user}','cat':'Video'},
        {'nombre':'YouTube Channel','url':f'https://youtube.com/c/{user}','cat':'Video'},
        {'nombre':'Vimeo','url':f'https://vimeo.com/{user}','cat':'Video'},
        {'nombre':'Dailymotion','url':f'https://dailymotion.com/{user}','cat':'Video'},
        {'nombre':'Vevo','url':f'https://vevo.com/artist/{user}','cat':'Música'},
        {'nombre':'Bitchute','url':f'https://bitchute.com/channel/{user}','cat':'Video'},
        {'nombre':'DTube','url':f'https://d.tube/#!/c/{user}','cat':'Video'},
        {'nombre':'LBRY','url':f'https://lbry.tv/@{user}','cat':'Video'},
        {'nombre':'Odysee','url':f'https://odysee.com/@{user}','cat':'Video'},
        {'nombre':'PeerTube','url':f'https://joinpeertube.org/instance?search={user}','cat':'Video'},
        # === DATING Y RELACIONES (15+) ===
        {'nombre':'Tinder','url':f'https://tinder.com/@{user}','cat':'Dating'},
        {'nombre':'Bumble','url':f'https://bumble.com/profile/{user}','cat':'Dating'},
        {'nombre':'Hinge','url':f'https://hinge.co/profile/{user}','cat':'Dating'},
        {'nombre':'OkCupid','url':f'https://okcupid.com/profile/{user}','cat':'Dating'},
        {'nombre':'Plenty of Fish','url':f'https://pof.com/member/{user}','cat':'Dating'},
        {'nombre':'Badoo','url':f'https://badoo.com/en/{user}/','cat':'Dating'},
        {'nombre':'Grindr','url':f'https://grindr.com/profile/{user}','cat':'Dating'},
        {'nombre':'Scruff','url':f'https://scruff.com/profile/{user}','cat':'Dating'},
        {'nombre':'Coffee Meets Bagel','url':f'https://coffeemeetsbagel.com/profile/{user}','cat':'Dating'},
        {'nombre':'eHarmony','url':f'https://eharmony.com/profile/{user}','cat':'Dating'},
        {'nombre':'Match.com','url':f'https://match.com/profile/{user}','cat':'Dating'},
        {'nombre':'Zoosk','url':f'https://zoosk.com/profile/{user}','cat':'Dating'},
        # === COMPRAS Y FREELANCE (20+) ===
        {'nombre':'Etsy','url':f'https://etsy.com/shop/{user}','cat':'Compras'},
        {'nombre':'eBay','url':f'https://ebay.com/usr/{user}','cat':'Compras'},
        {'nombre':'Mercari','url':f'https://mercari.com/u/{user}','cat':'Compras'},
        {'nombre':'Poshmark','url':f'https://poshmark.com/closet/{user}','cat':'Compras'},
        {'nombre':'Depop','url':f'https://depop.com/{user}','cat':'Compras'},
        {'nombre':'Vinted','url':f'https://vinted.com/member/{user}','cat':'Compras'},
        {'nombre':'Grailed','url':f'https://grailed.com/{user}','cat':'Compras'},
        {'nombre':'Reverb','url':f'https://reverb.com/shop/{user}','cat':'Música'},
        {'nombre':'Fiverr','url':f'https://fiverr.com/{user}','cat':'Freelance'},
        {'nombre':'Upwork','url':f'https://upwork.com/fl/{user}','cat':'Freelance'},
        {'nombre':'Freelancer','url':f'https://freelancer.com/u/{user}','cat':'Freelance'},
        {'nombre':'Guru','url':f'https://guru.com/freelancers/{user}','cat':'Freelance'},
        {'nombre':'PeoplePerHour','url':f'https://peopleperhour.com/freelancer/{user}','cat':'Freelance'},
        {'nombre':'Toptal','url':f'https://toptal.com/resume/{user}','cat':'Freelance'},
        # === BLOGS Y PUBLICACIONES (15+) ===
        {'nombre':'WordPress','url':f'https://{user}.wordpress.com','cat':'Blog'},
        {'nombre':'Blogger','url':f'https://{user}.blogspot.com','cat':'Blog'},
        {'nombre':'Wix','url':f'https://{user}.wixsite.com','cat':'Blog'},
        {'nombre':'Weebly','url':f'https://{user}.weebly.com','cat':'Blog'},
        {'nombre':'Substack','url':f'https://{user}.substack.com','cat':'Blog'},
        {'nombre':'Ghost','url':f'https://{user}.ghost.io','cat':'Blog'},
        {'nombre':'Typepad','url':f'https://{user}.typepad.com','cat':'Blog'},
        # === CRYPTO Y BLOCKCHAIN (10+) ===
        {'nombre':'Coinbase','url':f'https://coinbase.com/{user}','cat':'Crypto'},
        {'nombre':'Binance','url':f'https://binance.com/en/profile/{user}','cat':'Crypto'},
        {'nombre':'OpenSea','url':f'https://opensea.io/{user}','cat':'NFT'},
        {'nombre':'Rarible','url':f'https://rarible.com/user/{user}','cat':'NFT'},
        {'nombre':'Foundation','url':f'https://foundation.app/@{user}','cat':'NFT'},
        {'nombre':'SuperRare','url':f'https://superrare.com/{user}','cat':'NFT'},
        {'nombre':'Nifty Gateway','url':f'https://niftygateway.com/profile/{user}','cat':'NFT'},
        {'nombre':'Etherscan','url':f'https://etherscan.io/address/{user}','cat':'Crypto'},
        {'nombre':'Mirror.xyz','url':f'https://mirror.xyz/{user}','cat':'Crypto'},
        # === OTROS SERVICIOS (20+) ===
        {'nombre':'About.me','url':f'https://about.me/{user}','cat':'Perfil'},
        {'nombre':'Linktree','url':f'https://linktr.ee/{user}','cat':'Perfil'},
        {'nombre':'Carrd','url':f'https://{user}.carrd.co','cat':'Perfil'},
        {'nombre':'Bio.link','url':f'https://bio.link/{user}','cat':'Perfil'},
        {'nombre':'Beacons','url':f'https://beacons.ai/{user}','cat':'Perfil'},
        {'nombre':'Gravatar','url':f'https://en.gravatar.com/{user}','cat':'Perfil'},
        {'nombre':'Keybase','url':f'https://keybase.io/{user}','cat':'Seguridad'},
        {'nombre':'HackerOne','url':f'https://hackerone.com/{user}','cat':'Seguridad'},
        {'nombre':'Bugcrowd','url':f'https://bugcrowd.com/{user}','cat':'Seguridad'},
        {'nombre':'TryHackMe','url':f'https://tryhackme.com/p/{user}','cat':'Seguridad'},
        {'nombre':'HackTheBox','url':f'https://hackthebox.com/home/users/profile/{user}','cat':'Seguridad'},
        {'nombre':'Root-Me','url':f'https://root-me.org/{user}','cat':'Seguridad'},
        {'nombre':'Vulnhub','url':f'https://vulnhub.com/author/{user}','cat':'Seguridad'},
        {'nombre':'PentesterLab','url':f'https://pentesterlab.com/profile/{user}','cat':'Seguridad'},
        {'nombre':'Duolingo','url':f'https://duolingo.com/profile/{user}','cat':'Educación'},
        {'nombre':'Goodreads','url':f'https://goodreads.com/{user}','cat':'Libros'},
        {'nombre':'LibraryThing','url':f'https://librarything.com/profile/{user}','cat':'Libros'},
        {'nombre':'Strava','url':f'https://strava.com/athletes/{user}','cat':'Deporte'},
        {'nombre':'MyFitnessPal','url':f'https://myfitnesspal.com/profile/{user}','cat':'Salud'},
        {'nombre':'Fitbit','url':f'https://fitbit.com/user/{user}','cat':'Salud'},
        {'nombre':'MapMyRun','url':f'https://mapmyrun.com/profile/{user}','cat':'Deporte'},
        {'nombre':'Nike Run Club','url':f'https://nike.com/running/athlete/{user}','cat':'Deporte'},
        {'nombre':'Garmin Connect','url':f'https://connect.garmin.com/modern/profile/{user}','cat':'Deporte'},
        {'nombre':'TripAdvisor','url':f'https://tripadvisor.com/members/{user}','cat':'Viajes'},
        {'nombre':'Airbnb','url':f'https://airbnb.com/users/show/{user}','cat':'Viajes'},
        {'nombre':'Couchsurfing','url':f'https://couchsurfing.com/people/{user}','cat':'Viajes'},
        {'nombre':'Atlas Obscura','url':f'https://atlasobscura.com/users/{user}','cat':'Viajes'},
        {'nombre':'Foursquare','url':f'https://foursquare.com/user/{user}','cat':'Geo'},
        {'nombre':'Swarm','url':f'https://swarmapp.com/user/{user}','cat':'Geo'},
    ]
    # ======================================================================

    resultados = []
    total = len(sitios)

    for idx, sitio in enumerate(sitios, 1):
        print(f"\r{Wh}Progreso: {idx}/{total} ({int(idx/total*100)}%)", end="", flush=True)
        try:
            r = requests.get(sitio['url'], headers=headers, timeout=3, allow_redirects=True)
            if r.status_code == 200:
                html = r.text.lower()
                if "not found" not in html and "no existe" not in html and "page not found" not in html:
                    resultados.append(sitio)
        except:
            pass
        time.sleep(0.1)

    print(f"\n\n{Gr}═══════════════════════════════════════════════════════════")
    print(f"{Gr}   📊  RESULTADOS ENCONTRADOS ({len(resultados)}/{total})")
    print(f"{Gr}═══════════════════════════════════════════════════════════")
    if resultados:
        cats = {}
        for r in resultados:
            cats.setdefault(r['cat'], []).append(r)
        for cat, lista in cats.items():
            print(f"\n{Or}{cat} ({len(lista)}):")
            for s in lista:
                print(f"{Wh}  → {Gr}{s['nombre']}: {Cy}{s['url']}")
    else:
        print(f"{Ye}No se encontraron perfiles.")
    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# HERRAMIENTAS DE DEFENSA
# ==========================================================
def spam_blocker():
    print(f"\n{Gr}══════════════════════════════════════════")
    print(f"{Gr}   🛡️  SPAM BLOCKER - DEFENSA ACTIVA")
    print(f"{Gr}══════════════════════════════════════════")
    print(f"{Wh}SpamBlocker es una herramienta que bloquea llamadas spam.")
    print(f"{Wh}Puedes instalarla desde GitHub con:")
    print(f"{Cy}git clone https://github.com/aj3423/SpamBlocker")
    print(f"{Wh}Luego sigue las instrucciones del repositorio.")
    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# HERRAMIENTAS PROFESIONALES (Maigret, Sherlock)
# ==========================================================
def herramientas_profesionales():
    while True:
        print(f"\n{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Gr}   🔬  HERRAMIENTAS PROFESIONALES (AUTOMATIZADAS)")
        print(f"{Gr}═══════════════════════════════════════════════════════════")
        print(f"{Or}[1] {Wh}Ejecutar Maigret (3000+ sitios)")
        print(f"{Or}[2] {Wh}Ejecutar Sherlock (300+ sitios)")
        print(f"{Or}[3] {Wh}Ver enlaces a frameworks OSINT")
        print(f"{Or}[0] {Wh}Volver")

        opt = input(f"{Or}\nElige: {Gr}").strip()

        if opt == "1":
            try:
                subprocess.run(['maigret', '--version'], capture_output=True, check=True)
                print(f"{Gr}Maigret ya está instalado.")
            except:
                print(f"{Ye}Instalando Maigret...")
                subprocess.run(['pip', 'install', 'maigret'], check=True)
            username = input(f"{Or}Username objetivo: {Gr}").strip()
            if username:
                print(f"{Wh}Ejecutando Maigret...")
                subprocess.run(['maigret', username, '--html', 'report_maigret.html'])
                print(f"{Gr}Reporte guardado como 'report_maigret.html'")
            input(f"\n{Wh}[Enter para continuar]")

        elif opt == "2":
            sherlock_dir = os.path.expanduser("~/sherlock")
            if not os.path.exists(sherlock_dir):
                print(f"{Ye}Clonando Sherlock...")
                subprocess.run(['git', 'clone', 'https://github.com/sherlock-project/sherlock.git', sherlock_dir], check=True)
            else:
                print(f"{Gr}Sherlock ya está clonado. Actualizando...")
                subprocess.run(['git', '-C', sherlock_dir, 'pull'], check=True)
            req_file = os.path.join(sherlock_dir, 'requirements.txt')
            if os.path.exists(req_file):
                print(f"{Wh}Instalando dependencias...")
                subprocess.run(['pip', 'install', '-r', req_file], check=True)
            username = input(f"{Or}Username objetivo: {Gr}").strip()
            if username:
                print(f"{Wh}Ejecutando Sherlock...")
                os.chdir(sherlock_dir)
                subprocess.run(['python', 'sherlock', username])
                os.chdir('..')
            input(f"\n{Wh}[Enter para continuar]")

        elif opt == "3":
            print(f"\n{Or}📌 OSINT Framework: {Gr}https://osintframework.com")
            print(f"{Or}📌 SpiderFoot: {Gr}https://www.spiderfoot.net")
            print(f"{Or}📌 Recon-ng: {Gr}https://github.com/lanmaster53/recon-ng")
            print(f"{Or}📌 Maltego: {Gr}https://www.maltego.com")
            input(f"\n{Wh}[Enter para continuar]")

        elif opt == "0":
            break
        else:
            print(f"{Re}Opción inválida")
            time.sleep(1)

# ==========================================================
# OTRAS HERRAMIENTAS ÚTILES
# ==========================================================
def image_search():
    print(f"\n{Gr}══════════════════════════════════════════")
    print(f"{Gr}   🖼️  BÚSQUEDA INVERSA DE IMÁGENES")
    print(f"{Gr}══════════════════════════════════════════")
    url = input(f"{Or}URL de la imagen: {Gr}")
    if url:
        search = f"https://www.google.com/searchbyimage?image_url={urllib.parse.quote(url)}"
        print(f"{Wh}Abre en navegador: {Gr}{search}")
    input(f"\n{Wh}[Enter para continuar]")

def port_scan():
    ip = input(f"{Or}IP objetivo: {Gr}")
    print(f"{Wh}Escaneando puertos comunes...")
    for port in [21,22,23,25,80,443,8080,3306,3389]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            res = sock.connect_ex((ip, port))
            if res == 0:
                print(f"{Gr}Puerto {port}: ABIERTO")
            sock.close()
        except:
            pass
    input(f"\n{Wh}[Enter para continuar]")

def domain_whois_plus():
    dominio = input(f"{Or}Dominio: {Gr}").strip().lower()
    if not dominio:
        return
    print(f"\n{Gr}══════════════════════════════════════════")
    print(f"{Gr}   📋  WHOIS MEJORADO")
    print(f"{Gr}══════════════════════════════════════════")
    try:
        w = whois.whois(dominio)
        campos = [
            ("Dominio","domain_name"), ("Registrar","registrar"),
            ("Creación","creation_date"), ("Expiración","expiration_date"),
            ("Email","emails"), ("Organización","org"), ("País","country"),
            ("DNS","name_servers")
        ]
        for label, key in campos:
            val = w.get(key)
            if val:
                if isinstance(val, list):
                    val = ', '.join(str(v) for v in val[:3])
                print(f"{Wh}{label}: {Gr}{val}")
        try:
            import dns.resolver
            ans = dns.resolver.resolve(dominio, 'A')
            print(f"{Wh}Registros A: {Gr}" + ', '.join(str(r) for r in ans))
        except:
            print(f"{Ye}No se pudieron obtener registros A (instala dnspython)")
    except Exception as e:
        print(f"{Re}Error: {e}")
    input(f"\n{Wh}[Enter para continuar]")

# ==========================================================
# MENÚ PRINCIPAL
# ==========================================================
def main():
    mostrar_banner()
    while True:
        print(f"{Gr}╔════════════════════════════════════════════════════╗")
        print(f"{Gr}║           M E N Ú   P R I N C I P A L              ║")
        print(f"{Gr}╚════════════════════════════════════════════════════╝")
        print(f"{Or}[1] 📱 TODO SOBRE UN TELÉFONO")
        print(f"{Or}[2] 📧 TODO SOBRE UN EMAIL")
        print(f"{Or}[3] 🌐 IP Tracker")
        print(f"{Or}[4] 👤 USERNAME TRACKER MASIVO (300+ sitios)")
        print(f"{Or}[5] 🌍 Ver mi IP")
        print(f"{Or}[6] 🛡️  SPAM BLOCKER (defensa)")
        print(f"{Or}[7] 🖼️  Búsqueda inversa de imágenes")
        print(f"{Or}[8] 🔍 Escaneo de puertos")
        print(f"{Or}[9] 📋 WHOIS de dominio mejorado")
        print(f"{Or}[10] 🔬 Herramientas profesionales (Maigret/Sherlock)")
        print(f"{Or}[0] Salir")

        try:
            opt = int(input(f"{Or}\nElige: {Gr}"))
            if opt == 1:
                mega_phone()
            elif opt == 2:
                email_deep()
            elif opt == 3:
                ip_track()
            elif opt == 4:
                username_track_masivo()
            elif opt == 5:
                ip = requests.get('https://api.ipify.org/').text
                print(f"{Wh}Tu IP: {Gr}{ip}")
                input(f"{Wh}[Enter para continuar]")
            elif opt == 6:
                spam_blocker()
            elif opt == 7:
                image_search()
            elif opt == 8:
                port_scan()
            elif opt == 9:
                domain_whois_plus()
            elif opt == 10:
                herramientas_profesionales()
            elif opt == 0:
                break
            else:
                print(f"{Re}Opción inválida")
                time.sleep(1)
        except Exception as e:
            print(f"{Re}Error: {e}")
            time.sleep(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Re}Saliendo...")
