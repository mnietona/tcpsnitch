#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Verif arg
if [ "$#" -ne 2 ]; then
    echo -e "${BLUE}Usage: ./run_linux_test.sh <application> <scenario>${NC}"
    echo -e "Applications : 1=Telegram, 2=VLC (Flux Radio), 3=Transmission (BitTorrent)"
    echo -e "Scénarios    : 1=Normal, 2=Handover (Eth->WiFi), 3=Blackout (Coupure totale)"
    echo -e "Exemple      : ./run_linux_test.sh 3 1  (Lance Transmission en Normal)"
    exit 1
fi

APP_INPUT=$(echo "$1" | tr '[:upper:]' '[:lower:]')
SCENARIO_INPUT=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Application
case $APP_INPUT in
    1|telegram)
        APP_NAME="Telegram"
        APP_BIN="$HOME/Telegram/Telegram"
        APP_ARGS=""
        KILL_NAME="Telegram"
        ;;
    2|vlc)
        APP_NAME="VLC"
        APP_BIN="vlc"
        APP_ARGS="http://icecast.radiofrance.fr/fip-midfi.mp3"
        KILL_NAME="vlc"
        ;;
    3|transmission)
        APP_NAME="Transmission"
        APP_BIN="transmission-gtk"
        APP_ARGS=""
        KILL_NAME="transmission-gtk"
        ;;
    *)
        echo -e "${RED}❌ Application non reconnue. Utilisez 1, 2 ou 3.${NC}"
        exit 1
        ;;
esac

# Scenario
case $SCENARIO_INPUT in
    1|normal)   SCENARIO_NAME="Baseline (Standard 3m/1m)" ;;
    2|handover) SCENARIO_NAME="Handover (Ethernet -> Wi-Fi)" ;;
    3|blackout) SCENARIO_NAME="Black-out (Coupure totale 15s)" ;;
    *) echo -e "${RED} Scénario non reconnu. Utilisez 1, 2 ou 3.${NC}"; exit 1 ;;
esac

# Vérification de l'exécutable
if ! command -v "$APP_BIN" &> /dev/null && [ ! -f "$APP_BIN" ]; then
    echo -e "${RED} Exécutable introuvable : $APP_BIN${NC}"
    echo "Assurez-vous que l'application est bien installée."
    exit 1
fi

# Demande du mot de passe sudo en amont
echo -e "${BLUE}[INFO] TCPSnitch a besoin des droits root pour l'eBPF...${NC}"
sudo -v

# Identification de la carte Ethernet (pour le scénario Handover)
ETH_DEV=$(nmcli device status | grep ethernet | head -n 1 | awk '{print $1}')

# Nettoyage 
cleanup() {
    echo -e "\n\n${RED} Fin du test ou Interruption détectée.${NC}"
    
    echo -e "${BLUE}🧹 Arrêt de TCPSnitch et $APP_NAME...${NC}"

    sudo pkill -INT tcpsnitch 2>/dev/null
    pkill -f "$KILL_NAME" 2>/dev/null
    
    echo -e "${BLUE} estauration des paramètres réseaux...${NC}"
    nmcli networking on
    
    # SÉCURITÉ : On s'assure de supprimer le blocage si le script a été interrompu
    sudo iptables -D INPUT ! -i lo -j DROP 2>/dev/null
    sudo iptables -D OUTPUT ! -o lo -j DROP 2>/dev/null
    
    if [ ! -z "$ETH_DEV" ]; then
        nmcli device connect "$ETH_DEV" >/dev/null 2>&1
    fi
    
    echo -e "${GREEN} Test terminé ! Les données sont dans : $OUTPUT_DIR${NC}"
    exit 0
}

# Capture du Ctrl+C
trap cleanup SIGINT

# Debut
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=================================================="
echo -e "${PURPLE}Test   : $APP_NAME (Linux eBPF)${NC}"
echo -e "${PURPLE}Mode   : $SCENARIO_NAME${NC}"
echo -e "${YELLOW}Faites Ctrl+C à tout moment pour arrêter proprement.${NC}"
echo "=================================================="

# Préparation du réseau
nmcli networking on
if [ ! -z "$ETH_DEV" ]; then
    nmcli device connect "$ETH_DEV" >/dev/null 2>&1
fi
sleep 2

# Start
echo -e "${BLUE}[INFO] Lancement de TCPSnitch en arrière-plan...${NC}"

# Lancement de TCPSnitch avec les arguments
sudo -E tcpsnitch -e "$APP_BIN" $APP_ARGS > /dev/null 2>&1 &

echo -e "\n${GREEN}[0s] DÉMARREZ VOTRE ACTIVITÉ (Laissez l'application tourner)...${NC}"
if [ "$APP_INPUT" == "3" ] || [ "$APP_INPUT" == "transmission" ]; then
    echo -e "${YELLOW}👉 Pensez à glisser le fichier ubuntu.torrent dans Transmission !${NC}"
fi

if [ "$SCENARIO_INPUT" == "1" ]; then
    # SCENARIO 1 : NORMAL
    sleep 180

elif [ "$SCENARIO_INPUT" == "2" ]; then
    # SCENARIO 2 : HANDOVER
    if [ -z "$ETH_DEV" ]; then
        echo -e "${RED} ATTENTION : Aucune carte Ethernet détectée ! Le Handover risque de ne rien faire.${NC}"
    fi
    sleep 90
    echo -e "${YELLOW}[90s] COUPURE ETHERNET (Handover vers Wi-Fi en cours...)${NC}"
    nmcli device disconnect "$ETH_DEV" >/dev/null 2>&1
    sleep 90

elif [ "$SCENARIO_INPUT" == "3" ]; then
    # SCENARIO 3 : BLACK-OUT
    sleep 90
    echo -e "${RED}[90s] BLACK-OUT TOTAL (Blocage pare-feu de 15 secondes...)${NC}"
    
    # On bloque tout le trafic entrant/sortant (Sauf le réseau interne local 'lo')
    sudo iptables -I INPUT ! -i lo -j DROP
    sudo iptables -I OUTPUT ! -o lo -j DROP
    
    sleep 15
    
    echo -e "${GREEN}[105s] RETOUR DU RÉSEAU (Observation des retransmissions...)${NC}"
    
    # On retire les blocages
    sudo iptables -D INPUT ! -i lo -j DROP
    sudo iptables -D OUTPUT ! -o lo -j DROP
    
    sleep 75
fi

echo -e "\n${PURPLE}====================================================${NC}"
echo -e "${PURPLE}[180s] Attention : Mettre le torrent en PAUSE)${NC}"
echo -e "${PURPLE}====================================================${NC}"
sleep 60

# Appel manuel du cleanup
cleanup