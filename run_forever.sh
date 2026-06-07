#!/usr/bin/env bash
# =============================================================================
# GUARDIAN — Relance infinie (Unix/macOS)
# =============================================================================
# Lance guardian.py sur BSC+ETH et le relance automatiquement s'il s'arrête.
# Loggue tout dans guardian_output.log avec timestamps.
#
# Usage:
#     chmod +x run_forever.sh
#     ./run_forever.sh
#
# Pour arrêter : Ctrl+C deux fois (une pour guardian, une pour le script)
# =============================================================================

cd "$(dirname "$0")"

LOG_FILE="guardian_output.log"
RESTART_DELAY=10  # secondes avant de relancer
MAX_RESTARTS=99999
restart_count=0

echo "================================================================" | tee -a "$LOG_FILE"
echo "  GUARDIAN — FOREVER MODE (BSC + ETH)" | tee -a "$LOG_FILE"
echo "  Démarré: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "  Log: $LOG_FILE" | tee -a "$LOG_FILE"
echo "  Redémarrage automatique après $RESTART_DELAY sec si crash" | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"

cleanup() {
    echo "" | tee -a "$LOG_FILE"
    echo "[$(date '+%H:%M:%S')] ARRÊT — $restart_count redémarrages effectués" | tee -a "$LOG_FILE"
    exit 0
}
trap cleanup SIGINT SIGTERM

while [ $restart_count -lt $MAX_RESTARTS ]; do
    restart_count=$((restart_count + 1))
    echo "" | tee -a "$LOG_FILE"
    echo "[$(date '+%H:%M:%S')] LANCEMENT #$restart_count" | tee -a "$LOG_FILE"
    echo "----------------------------------------" | tee -a "$LOG_FILE"

    # Run guardian with explicit chains (ETH+BSC only)
    python guardian.py --chains ethereum,bsc 2>&1 | tee -a "$LOG_FILE"

    EXIT_CODE=$?
    echo "[$(date '+%H:%M:%S')] Guardian arrêté (exit=$EXIT_CODE)" | tee -a "$LOG_FILE"

    # Quick commit of any new results before restart
    git add -A 2>/dev/null
    git commit -m "Auto: results after restart #$restart_count (exit=$EXIT_CODE)" 2>/dev/null
    git push origin master 2>/dev/null

    # Pause before restarting
    echo "[$(date '+%H:%M:%S')] Redémarrage dans ${RESTART_DELAY}s..." | tee -a "$LOG_FILE"
    sleep $RESTART_DELAY
done

echo "[$(date '+%H:%M:%S')] MAX_RESTARTS atteint ($MAX_RESTARTS). Arrêt." | tee -a "$LOG_FILE"
