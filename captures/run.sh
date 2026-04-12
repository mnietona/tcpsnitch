#!/bin/bash

cd "$(dirname "$0")" || exit 1

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# --- ANALYSE DES ARGUMENTS ---
FORCE_TCP=0
if [ "$1" == "tcp" ]; then
    FORCE_TCP=1
    echo -e "${BLUE}[INFO] Mode TCP exclusif activé (HTTP/3 désactivé).${NC}"
else
    echo -e "${PURPLE}[INFO] Mode standard (HTTP/3 possible). Capture QLOG activée.${NC}"
fi

# --- Fonction de nettoyage ---
cleanup() {
    echo -e "\n${GREEN}=== ÉTAPE 7 : Nettoyage ===${NC}"
    pkill -9 -f firefox 2>/dev/null
    pkill -9 tcpsnitch 2>/dev/null
    rm -rf "$(pwd)/ff_profile"
    echo -e "${BLUE}[INFO] Fin de session.${NC}"
}
trap cleanup EXIT SIGINT

echo -e "${GREEN}=== ÉTAPE 1 : Nettoyage processus ===${NC}"
pkill -9 -f firefox 2>/dev/null
pkill -9 tcpsnitch 2>/dev/null
sleep 2

echo -e "${GREEN}=== ÉTAPE 2 : Compilation ===${NC}"
make -C .. clean && make -C ..
if [ $? -ne 0 ]; then exit 1; fi

echo -e "${GREEN}=== ÉTAPE 3 : Profil Firefox ===${NC}"
rm -rf ff_profile && mkdir -p ff_profile
cat <<EOF > ff_profile/user.js
user_pref("app.update.auto", false);
user_pref("app.update.enabled", false);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.connectivity-service.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("browser.startup.homepage", "about:blank");
EOF

if [ "$FORCE_TCP" -eq 1 ]; then
    echo 'user_pref("network.http.http3.enable", false);' >> ff_profile/user.js
else
    # Si on est en HTTP/3, on prépare le dossier QLOG unique
    QLOG_DIR="$(pwd)/qlogs/run_$TIMESTAMP"
    mkdir -p "$QLOG_DIR"
    
    # Variables d'environnement pour forcer l'export QLOG
    export MOZ_HTTP3_QLOG="$QLOG_DIR"
    # Optionnel : MOZ_LOG permet d'avoir plus de détails dans la console/logs
    # export MOZ_LOG="quic:5,nsHttp:5" 
    
    echo -e "${PURPLE}[QLOG] Les fichiers seront sauvegardés dans : $QLOG_DIR${NC}"
fi

echo -e "${GREEN}=== ÉTAPE 4 : Firefox Check ===${NC}"
if [ ! -f "$(pwd)/firefox/firefox-bin" ]; then
    echo "Téléchargement de Firefox..."
    wget -O firefox.tar.xz "https://download.mozilla.org/?product=firefox-latest-ssl&os=linux64&lang=fr"
    tar -xf firefox.tar.xz && rm firefox.tar.xz
fi

echo -e "${GREEN}=== ÉTAPE 6 : Lancement ===${NC}"
export MOZ_DISABLE_CONTENT_SANDBOX=1
export MOZ_DISABLE_SOCKET_PROCESS_SANDBOX=1
export MOZ_CRASHREPORTER_DISABLE=1
export MOZ_DISABLE_HANG_MONITOR=1

tcpsnitch -- "$(pwd)/firefox/firefox-bin" -no-remote -profile "$(pwd)/ff_profile"