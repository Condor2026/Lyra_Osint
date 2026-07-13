#!/bin/bash
# ==========================================================
# Script de instalación para LYRA OSINT
# ==========================================================

# Colores para mejor visualización
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # Sin color

echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗"
echo -e "${CYAN}║                                                                  ║"
echo -e "${CYAN}║${GREEN}         ██╗    ██╗   ██╗██████╗  █████╗                   ║"
echo -e "${CYAN}║${GREEN}         ██║    ╚██╗ ██╔╝██╔══██╗██╔══██╗                  ║"
echo -e "${CYAN}║${GREEN}         ██║     ╚████╔╝ ██████╔╝███████║                  ║"
echo -e "${CYAN}║${GREEN}         ██║      ╚██╔╝  ██╔══██╗██╔══██║                  ║"
echo -e "${CYAN}║${GREEN}         ███████╗  ██║   ██║  ██║██║  ██║                  ║"
echo -e "${CYAN}║${GREEN}         ╚══════╝  ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝                  ║"
echo -e "${CYAN}║                                                                  ║"
echo -e "${CYAN}║${PURPLE}                  ✧  L Y R A  P R O  ✧                    ║"
echo -e "${CYAN}║${YELLOW}            🔍 OSINT Ético para Investigadores             ║"
echo -e "${CYAN}║${NC}                                                                  ║"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${GREEN}[✓] Iniciando instalación de LYRA...${NC}\n"

# ==========================================================
# DETECTAR SISTEMA OPERATIVO
# ==========================================================
if [ -f /data/data/com.termux/files/usr/bin/termux-setup-storage ]; then
    OS="termux"
    echo -e "${BLUE}[i] Sistema detectado: Termux (Android)${NC}"
elif [ -f /etc/debian_version ]; then
    OS="debian"
    echo -e "${BLUE}[i] Sistema detectado: Debian/Ubuntu/Kali${NC}"
elif [ -f /etc/redhat-release ]; then
    OS="redhat"
    echo -e "${BLUE}[i] Sistema detectado: RedHat/CentOS/Fedora${NC}"
else
    OS="unknown"
    echo -e "${YELLOW}[!] Sistema no reconocido, usando método genérico${NC}"
fi

# ==========================================================
# ACTUALIZAR SISTEMA
# ==========================================================
echo -e "\n${CYAN}[1/6] Actualizando sistema...${NC}"

case $OS in
    termux)
        pkg update && pkg upgrade -y
        ;;
    debian)
        sudo apt update && sudo apt upgrade -y
        ;;
    redhat)
        sudo yum update -y
        ;;
    *)
        echo -e "${YELLOW}[!] Saltando actualización del sistema${NC}"
        ;;
esac

# ==========================================================
# INSTALAR PYTHON Y GIT
# ==========================================================
echo -e "\n${CYAN}[2/6] Instalando Python y Git...${NC}"

case $OS in
    termux)
        pkg install python python-pip git -y
        ;;
    debian)
        sudo apt install python3 python3-pip git -y
        ;;
    redhat)
        sudo yum install python3 python3-pip git -y
        ;;
    *)
        echo -e "${YELLOW}[!] Instalando con pip...${NC}"
        pip install --upgrade pip
        ;;
esac

# ==========================================================
# INSTALAR DEPENDENCIAS DE PYTHON
# ==========================================================
echo -e "\n${CYAN}[3/6] Instalando dependencias de Python...${NC}"

# Dependencias principales
DEPENDENCIAS=(
    "requests"
    "phonenumbers"
    "whois"
    "dnspython"
    "pyyaml"
    "geopy"
    "pywhatkit"
)

for dep in "${DEPENDENCIAS[@]}"; do
    echo -e "${BLUE}[i] Instalando $dep...${NC}"
    pip install $dep --quiet 2>/dev/null || pip3 install $dep --quiet 2>/dev/null
done

echo -e "${GREEN}[✓] Dependencias instaladas${NC}"

# ==========================================================
# CLONAR REPOSITORIO
# ==========================================================
echo -e "\n${CYAN}[4/6] Clonando repositorio...${NC}"

if [ -d "Lyra_Osint" ]; then
    echo -e "${YELLOW}[!] El directorio Lyra_Osint ya existe${NC}"
    echo -e "${BLUE}[i] Actualizando repositorio...${NC}"
    cd Lyra_Osint
    git pull
    cd ..
else
    git clone https://github.com/Condor2026/Lyra_Osint.git
fi

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Repositorio clonado correctamente${NC}"
else
    echo -e "${RED}[✗] Error al clonar el repositorio${NC}"
    echo -e "${YELLOW}[i] Verifica tu conexión a Internet${NC}"
    exit 1
fi

# ==========================================================
# PERMISOS Y CONFIGURACIÓN
# ==========================================================
echo -e "\n${CYAN}[5/6] Configurando permisos...${NC}"

cd Lyra_Osint

# Dar permisos de ejecución
chmod +x lyra.py 2>/dev/null

# Crear directorios necesarios
mkdir -p output
mkdir -p cache
mkdir -p logs

echo -e "${GREEN}[✓] Directorios creados${NC}"

# ==========================================================
# COMPROBAR INSTALACIÓN
# ==========================================================
echo -e "\n${CYAN}[6/6] Verificando instalación...${NC}"

if [ -f "lyra.py" ]; then
    echo -e "${GREEN}✅ LYRA instalado correctamente${NC}"
else
    echo -e "${RED}❌ No se encontró lyra.py${NC}"
    exit 1
fi

# ==========================================================
# RESULTADO FINAL
# ==========================================================
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════════╗"
echo -e "${GREEN}║                                                                  ║"
echo -e "${GREEN}║                    ✨ INSTALACIÓN COMPLETA ✨                    ║"
echo -e "${GREEN}║                                                                  ║"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}📌 Para ejecutar LYRA:${NC}"
echo -e "${WHITE}   cd Lyra_Osint${NC}"
echo -e "${WHITE}   python lyra.py${NC}"
echo -e "${WHITE}   python3 lyra.py${NC}"

echo -e "\n${CYAN}📚 Comandos útiles:${NC}"
echo -e "${WHITE}   • python lyra.py -h      # Ayuda${NC}"
echo -e "${WHITE}   • python lyra.py --update # Actualizar${NC}"

echo -e "\n${YELLOW}⚠️  Recuerda: LYRA es para fines educativos y legales${NC}"
echo -e "${YELLOW}   Usa la herramienta de manera ética y responsable${NC}"

echo -e "\n${GREEN}✅ ¡Listo!${NC}"
