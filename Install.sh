#!/bin/bash
# Script de instalación para LYRA

echo "Instalando dependencias..."
pkg update && pkg upgrade -y
pkg install python git -y
pip install requests phonenumbers whois dnspython

echo "Clonando repositorio..."
git clone https://github.com/tu-usuario/LYRA.git
cd LYRA

echo "Instalación completada. Ejecuta: python lyra.py"
