#!/bin/bash
# ============================================================
# Script de test de scalabilité pour l'API bancaire
# Utilise 'hey' pour envoyer une charge sur plusieurs endpoints
# ============================================================

set -e  # Arrêt en cas d'erreur

# ------------------------- CONFIGURATION -------------------------
BASE_URL="http://localhost:5000/api/v1"   # Adresse de votre API (locale ou Render)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc3NjM1Mjk1MiwianRpIjoiNzM4N2ExMDMtNjAyYS00ODgzLTgzOTMtMWJiZjVjMzE4NDM3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IjFhMWZjNDQyLWY5YmItNGFmYi04YTE1LTY0NWVkMzY4MDMxZCIsIm5iZiI6MTc3NjM1Mjk1MiwiY3NyZiI6ImRjMGQ0OWQ5LWRlYmMtNDdkNS1iMTkyLWNhODkwNzFkNTUzNyIsImV4cCI6MTc3NjM2MDE1Mn0.p83t8d2IBNVFZ5r0SPF_SlFZgwKp0mQRBKivgN8L100"

# Paramètres de charge (ajustez selon vos besoins)
CONCURRENCY=200        # Nombre de requêtes simultanées
DURATION="30s"         # Durée du test (ex: 30s, 1m)
# Alternative: utiliser un nombre fixe de requêtes (décommentez la ligne suivante et commentez DURATION)
# REQUESTS=10000

# En-têtes communs (ex: Accept JSON, user-agent personnalisé)
COMMON_HEADERS=(
    "-H" "Accept: application/json"
    "-H" "User-Agent: Hey-Scalability-Test"
)

# Dossiers de résultats (optionnel)
RESULTS_DIR="./scalability_results"
mkdir -p "$RESULTS_DIR"

# ------------------------- FONCTIONS -------------------------
function run_test() {
    local endpoint=$1
    local need_auth=$2
    local description=$3
    local url="${BASE_URL}${endpoint}"
    
    echo "============================================================"
    echo "📊 Test : $description ($endpoint)"
    echo "   Concurrence : $CONCURRENCY | Durée : $DURATION"
    echo "============================================================"
    
    # Construction de la commande hey
    local cmd="hey"
    
    # Choix entre durée ou nombre fixe
    if [ -n "$DURATION" ]; then
        cmd="$cmd -z $DURATION"
    elif [ -n "$REQUESTS" ]; then
        cmd="$cmd -n $REQUESTS"
    else
        echo "ERREUR: ni DURATION ni REQUESTS n'est défini"
        exit 1
    fi
    
    cmd="$cmd -c $CONCURRENCY -m GET"
    
    # Ajout des en-têtes communs
    for h in "${COMMON_HEADERS[@]}"; do
        cmd="$cmd $h"
    done
    
    # Ajout du token si nécessaire
    if [ "$need_auth" = "true" ]; then
        cmd="$cmd -H \"Authorization: Bearer $TOKEN\""
    fi
    
    # Ajout de l'URL
    cmd="$cmd \"$url\""
    
    # Exécution et redirection vers un fichier (optionnel) + affichage console
    local output_file="${RESULTS_DIR}/$(echo $endpoint | tr '/' '_')_c${CONCURRENCY}.log"
    echo "   => Sauvegarde dans $output_file"
    
    # Lancer la commande et enregistrer la sortie (stdout + stderr)
    eval "$cmd" 2>&1 | tee "$output_file"
    
    echo ""
    echo "✅ Test terminé pour $endpoint"
    echo "   Résultats détaillés : $output_file"
    echo ""
    sleep 2
}

# ------------------------- LANCEMENT DES TESTS -------------------------
echo "🚀 DÉBUT DES TESTS DE SCALABILITÉ"
echo "Base URL : $BASE_URL"
echo "Concurrence : $CONCURRENCY"
if [ -n "$DURATION" ]; then echo "Durée : $DURATION"; fi
if [ -n "$REQUESTS" ]; then echo "Requêtes totales : $REQUESTS"; fi
echo ""

# 1. Endpoint public (sans authentification)
run_test "/health" "false" "Santé du service"

# 2. Endpoints nécessitant un admin (token JWT)
run_test "/admin/users" "true" "Liste des utilisateurs (admin)"
run_test "/admin/audit" "true" "Journal d'audit (admin)"

# 3. Endpoints utilisateur authentifié (non-admin mais avec token valide)
run_test "/accounts" "true" "Liste des comptes de l'utilisateur"
run_test "/transactions" "true" "Historique des transactions"

# Optionnel : détail d'un utilisateur spécifique (remplacer par un ID réel)
# USER_ID="1a1fc442-f9bb-4afb-8a15-645ed368031d"
# run_test "/admin/users/${USER_ID}" "true" "Détail d'un utilisateur (admin)"

echo "============================================================"
echo "🏁 TOUS LES TESTS SONT TERMINÉS"
echo "Les résultats sont dans le dossier : $RESULTS_DIR"
echo "============================================================"