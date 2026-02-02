import streamlit as st

# Configuration de la page
st.set_page_config(page_title="TCPSnitch Analyzer", layout="centered")

# Titre et Message de Bienvenue
st.title("Bienvenue sur TCPSnitch Analyzer")

st.success("La connexion avec Streamlit Cloud est réussie !")

st.markdown("""
### Prochaines étapes :
L'interface d'analyse complète arrivera bientôt. 
Elle vous permettra de :
1. **Uploader** vos archives `.tar.gz`.
2. **Visualiser** les appels systèmes (Splice, Sendfile...).
3. **Analyser** la mobilité (MPTCP / Netlink).
""")

st.info("En attente de la mise à jour du code... ")
