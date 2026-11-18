#!/usr/bin/env bash
# Setup script per JS Crawler v2
set -euo pipefail

echo "Setup JS Crawler v2..."

if ! command -v python3 &> /dev/null; then
    echo "Python3 non trovato. Installalo prima di continuare."
    exit 1
fi
echo "Python3 trovato: $(python3 --version)"

# Su Debian/Parrot/Kali il modulo venv e' un pacchetto a parte
if ! python3 -c "import venv, ensurepip" &> /dev/null; then
    echo "Modulo venv mancante. Installa con: sudo apt install python3-venv"
    exit 1
fi

echo "Creo il virtual environment..."
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate

echo "Installo le dipendenze..."
pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f "sites.txt" ]; then
    echo "Creo sites.txt di esempio..."
    cat > sites.txt << 'SITES'
# Un target per riga. Le righe che iniziano con # sono commenti.
# Accettati: URL completi, host senza schema, wildcard (*.dominio.it = regola di scope)
#
# ATTENZIONE: crawla solo siti per cui hai un'autorizzazione!
https://example.com
# *.example.com
SITES
fi

mkdir -p js_downloads rules

# Regole di gitleaks per l'analisi dei segreti (opzionale: senza, l'analyzer usa solo rules/extra_secrets.toml)
if [ ! -f "rules/gitleaks.toml" ]; then
    echo "Scarico le regole di gitleaks..."
    curl -fsSL -o rules/gitleaks.toml \
        https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml \
        || echo "Download non riuscito: scaricalo a mano in rules/gitleaks.toml (vedi js_analyzer.py --help)"
fi

echo
echo "Setup completato."
echo
echo "Come usare:"
echo "  1. source venv/bin/activate"
echo "  2. modifica sites.txt con i tuoi target autorizzati"
echo "  3. python js_crawler.py -f sites.txt --analyze   (crawl + analisi; opzioni: --help)"
echo "     python js_analyzer.py js_downloads            (solo analisi di file gia scaricati)"
echo "     python js_analyzer.py --check-rules           (verifica le regole caricate)"
echo
echo "IMPORTANTE: usa solo su siti per cui hai autorizzazione!"