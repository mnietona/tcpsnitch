#!/bin/bash

# Verif arg
if [ "$#" -ne 2 ]; then
    echo "Usage: ./run_test.sh <application> <scenario>"
    echo "Applications : 1=discord, 2=messenger, 3=twitch, 4=tiktok, 5=facebook"
    echo "Scénarios    : 1=normal, 2=handover, 3=blackout"
    exit 1
fi

APP_INPUT=$(echo "$1" | tr '[:upper:]' '[:lower:]')
SCENARIO_INPUT=$(echo "$2" | tr '[:upper:]' '[:lower:]')

# Application
case $APP_INPUT in
    1|discord)     APP_NAME="Discord";      PACKAGE="com.discord" ;;
    2|messenger)   APP_NAME="Messenger";    PACKAGE="com.facebook.orca" ;;
    3|twitch)      APP_NAME="Twitch";       PACKAGE="tv.twitch.android.app" ;;
    4|tiktok)      APP_NAME="TikTok";       PACKAGE="com.zhiliaoapp.musically" ;;
    5|facebook)    APP_NAME="Facebook";     PACKAGE="com.facebook.katana" ;;
    *) echo " Application non reconnue : $APP_INPUT"; exit 1 ;;
esac

# Scénario
case $SCENARIO_INPUT in
    1|normal)   SCENARIO_NAME="Normal (WiFi continu)" ;;
    2|handover) SCENARIO_NAME="Handover (WiFi -> 4G)" ;;
    3|blackout) SCENARIO_NAME="Black-out (Coupure totale)" ;;
    *) echo " Scénario non reconnu. Utilisez 1, 2 ou 3."; exit 1 ;;
esac

# Nettoyage 
cleanup() {
    echo -e "\n\n Fin du script ou Interruption (Ctrl+C) détectée."
    echo "🧹 Fermeture de la capture pour $APP_NAME ($PACKAGE)..."
    tcpsnitch -k "$PACKAGE"
    
    echo "Restauration des paramètres réseaux par défaut..."
    adb shell svc wifi enable
    adb shell svc data enable
    
    # Fermer apps 
    # adb shell am force-stop "$PACKAGE"
    
    echo "Nettoyage terminé. À bientôt !"
    exit 0
}

trap cleanup SIGINT

# Debut
echo "=================================================="
echo "Test   : $APP_NAME"
echo "Mode   : $SCENARIO_NAME"
echo "Faites Ctrl+C à tout moment pour arrêter proprement."
echo "=================================================="


# Check conditions initiales
if [ "$SCENARIO_INPUT" == "3" ] || [ "$SCENARIO_INPUT" == "blackout" ]; then
    adb shell svc data disable
else
    adb shell svc data enable
fi
adb shell svc wifi enable
sleep 3 # Laisse le temps au réseau de se stabiliser


# Lancement tcpsnitch
tcpsnitch -a  "$PACKAGE" &

echo "[0s] Démarrez votre activité (Scroll/Appel/Message) pendant 3 minutes..."

if [ "$SCENARIO_INPUT" == "1" ] || [ "$SCENARIO_INPUT" == "normal" ]; then
    # SCENARIO 1 : NORMAL
    sleep 180

elif [ "$SCENARIO_INPUT" == "2" ] || [ "$SCENARIO_INPUT" == "handover" ]; then
    # SCENARIO 2 : HANDOVER
    sleep 90
    echo "[90s] COUPURE WIFI (Handover vers la 4G)..."
    adb shell svc wifi disable
    sleep 90

elif [ "$SCENARIO_INPUT" == "3" ] || [ "$SCENARIO_INPUT" == "blackout" ]; then
    # SCENARIO 3 : BLACK-OUT (Coupure de 15 secondes)
    sleep 90
    echo "[90s] COUPURE TOTALE (Zone morte de 15 secondes)..."
    adb shell svc wifi disable
    sleep 15
    
    echo "[105s] RETOUR DU WIFI (Observation du rattrapage)..."
    adb shell svc wifi enable
    sleep 75 # 90s + 15s + 75s = 180s d'action totale
fi

echo "[180s] Arrêtez de toucher au téléphone (1 minute de repos)..."
sleep 60

# Appel manuel du cleanup pour finir proprement
cleanup