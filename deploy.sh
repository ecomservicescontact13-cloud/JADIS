#!/bin/bash
# ──────────────────────────────────────────────────────────────
#  JADIS — Script de déploiement automatique
#  Usage : double-cliquer sur ce fichier OU lancer dans le terminal
#          bash deploy.sh "description de la modif"
# ──────────────────────────────────────────────────────────────

MESSAGE=${1:-"Mise à jour JADIS — $(date '+%d/%m/%Y %H:%M')"}

echo ""
echo "  JADIS — Déploiement en cours..."
echo "  Message : $MESSAGE"
echo ""

git add -A
git commit -m "$MESSAGE"
git push origin main

echo ""
echo "  Déployé avec succès."
echo "  GitHub Actions redéploiera le site dans ~1 minute."
echo ""
