#!/usr/bin/env bash
# =============================================================================
# GUARDIAN — Relance infinie (Unix/macOS)
# =============================================================================
# Lance guardian.py sur BSC+ETH et le relance automatiquement.
# Loggue tout dans guardian_output.log + findings/scanned_contracts.md
# JAMAIS de git push (mode autonome offline)
#
# Usage:    chmod +x run_forever.sh && ./run_forever.sh
# Stop:     Ctrl+C deux fois
# =============================================================================

cd "$(dirname "$0")"

LOG_FILE="guardian_output.log"
RESTART_DELAY=10
MAX_RESTARTS=99999
restart_count=0

echo "================================================================" | tee -a "$LOG_FILE"
echo "  GUARDIAN — FOREVER MODE (8 EVM chains)" | tee -a "$LOG_FILE"
echo "  Démarré: $(date '+%Y-%m-%d %H:%M:%S')" | tee -a "$LOG_FILE"
echo "  Log: $LOG_FILE" | tee -a "$LOG_FILE"
echo "  Redémarrage automatique. Mode: NO PUSH." | tee -a "$LOG_FILE"
echo "================================================================" | tee -a "$LOG_FILE"

cleanup() {
    echo "" | tee -a "$LOG_FILE"
    echo "[$(date '+%H:%M:%S')] ARRÊT — $restart_count restart(s)" | tee -a "$LOG_FILE"
    python dump_results.py "STOPPED_after_${restart_count}_restarts" 2>&1 | tee -a "$LOG_FILE"
    exit 0
}
trap cleanup SIGINT SIGTERM

while [ $restart_count -lt $MAX_RESTARTS ]; do
    restart_count=$((restart_count + 1))
    echo "" | tee -a "$LOG_FILE"
    echo "[$(date '+%H:%M:%S')] === LANCEMENT #$restart_count ===" | tee -a "$LOG_FILE"

    python guardian.py --chains ethereum,bsc,arbitrum,optimism,avalanche,polygon --force-hardhat 2>&1 | tee -a "$LOG_FILE"

    EXIT_CODE=${PIPESTATUS[0]}
    echo "[$(date '+%H:%M:%S')] Guardian stopped (exit=$EXIT_CODE)" | tee -a "$LOG_FILE"

    # Dump current results to findings/scanned_contracts.md
    python dump_results.py "restart_${restart_count}" 2>&1 | tee -a "$LOG_FILE"

    echo "[$(date '+%H:%M:%S')] Restart in ${RESTART_DELAY}s..." | tee -a "$LOG_FILE"
    sleep $RESTART_DELAY
done

echo "[$(date '+%H:%M:%S')] MAX_RESTARTS reached ($MAX_RESTARTS)." | tee -a "$LOG_FILE"
