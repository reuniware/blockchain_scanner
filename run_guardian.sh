#!/bin/bash
# =============================================================================
# run_guardian.sh - Lancer Guardian en arriere-plan 24/7
# =============================================================================
# Usage:
#   ./run_guardian.sh              # Demarrer dans tmux
#   ./run_guardian.sh --status     # Voir le statut
#   ./run_guardian.sh --attach     # Rejoindre la session
#   ./run_guardian.sh --stop       # Arreter proprement
# =============================================================================

SESSION_NAME="guardian"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "${1:-start}" in
    start)
        echo "[GUARDIAN] Demarrage de l'usine de detection..."
        echo "[GUARDIAN] Session tmux: $SESSION_NAME"
        echo "[GUARDIAN] Logs: guardian_output.log"
        echo ""

        # Creer la session tmux en arriere-plan
        tmux new-session -d -s "$SESSION_NAME" -n "guardian" \
            "python guardian.py 2>&1 | tee guardian_output.log"

        # Verifier que la session a demarre
        sleep 1
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            echo "[OK] Guardian tourne dans tmux session '$SESSION_NAME'"
            echo ""
            echo "  Commandes:"
            echo "    ./run_guardian.sh --attach    # Voir les logs en direct"
            echo "    ./run_guardian.sh --status    # Voir le statut"
            echo "    ./run_guardian.sh --stop      # Arreter"
            echo ""
            echo "  Pour detacher: Ctrl+B, puis D"
        else
            echo "[FAIL] Erreur de demarrage"
            exit 1
        fi
        ;;

    attach)
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            tmux attach-session -t "$SESSION_NAME"
        else
            echo "[GUARDIAN] Aucune session en cours."
            echo "  Demarrez avec: ./run_guardian.sh start"
            exit 1
        fi
        ;;

    status)
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            echo "[GUARDIAN] Session active"
            tmux capture-pane -t "$SESSION_NAME" -p | tail -20
            echo ""
            echo "  Dernieres lignes de log ci-dessus."
            echo "  Statut complet: ./run_guardian.sh --attach"
            python guardian.py --status 2>/dev/null || echo "  (base de donnees pas encore creee)"
        else
            echo "[GUARDIAN] Aucune session en cours."
            python guardian.py --status 2>/dev/null || true
        fi
        ;;

    stop)
        if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
            echo "[GUARDIAN] Arret de la session..."
            tmux send-keys -t "$SESSION_NAME" C-c  # Envoyer Ctrl+C
            sleep 2
            tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
            echo "[OK] Guardian arrete."
            echo "  Voir les logs: cat guardian_output.log"
        else
            echo "[GUARDIAN] Aucune session en cours."
        fi
        ;;

    *)
        echo "Usage: $0 {start|attach|status|stop}"
        exit 1
        ;;
esac
