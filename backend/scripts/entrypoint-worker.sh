#!/bin/sh
# =============================================================================
# entrypoint-worker.sh
# Prüft/repariert Tool-Binaries, aktualisiert Nuclei-Templates, dann Celery
# =============================================================================
set -e

echo "[entrypoint] Warte auf Redis..."
until python -c "
import redis, os
r = redis.from_url(os.environ['REDIS_URL'])
r.ping()
print('Redis bereit')
" 2>/dev/null; do
    sleep 2
done

# ── Binary-Verifikation und Selbstreparatur ───────────────────────────────────
# shutil.which() findet Binaries anhand von Dateiexistenz + X_OK, prüft aber
# nicht ob das ELF tatsächlich ausgeführt werden kann.  Typischer Fehler:
# Alpine/musl-kompiliertes Binary in einem Debian/glibc-Container.
# Wir führen jeden Tool einmal mit -version aus; wenn der Kernel ENOENT
# zurückgibt, laden wir das korrekte Architektur-Binary von GitHub herunter.

ARCH="$(dpkg --print-architecture 2>/dev/null || uname -m)"
case "$ARCH" in
  amd64|x86_64)   GOARCH=amd64 ;;
  arm64|aarch64)  GOARCH=arm64 ;;
  *)               GOARCH=amd64 ;;
esac

_verify_or_reinstall() {
  BIN="$1"
  VERSION="$2"
  URL="$3"

  BIN_PATH="$(command -v "$BIN" 2>/dev/null || true)"
  if [ -z "$BIN_PATH" ]; then
    echo "[entrypoint] ✗ ${BIN} nicht im PATH"
    return 1
  fi

  # Try executing it — catches musl/glibc ELF mismatch that shutil.which misses
  if "$BIN_PATH" -version >/dev/null 2>&1 || "$BIN_PATH" --version >/dev/null 2>&1; then
    echo "[entrypoint] ✓ ${BIN} OK (${BIN_PATH})"
    return 0
  fi

  echo "[entrypoint] ✗ ${BIN} nicht ausführbar (ELF/libc Mismatch?) — lade ${VERSION} herunter..."
  TMP_DIR="$(mktemp -d)"
  if wget -qO "${TMP_DIR}/${BIN}.zip" "$URL" 2>&1; then
    unzip -q "${TMP_DIR}/${BIN}.zip" -d "${TMP_DIR}" && \
    mv "${TMP_DIR}/${BIN}" /usr/local/bin/"${BIN}" && \
    chmod +x /usr/local/bin/"${BIN}" && \
    echo "[entrypoint] ✓ ${BIN} ${VERSION} erfolgreich installiert (${GOARCH})" || \
    echo "[entrypoint] ✗ ${BIN} Installation fehlgeschlagen"
  else
    echo "[entrypoint] ✗ ${BIN} Download fehlgeschlagen — fahre ohne fort"
  fi
  rm -rf "$TMP_DIR"
}

_verify_or_reinstall nuclei   "v3.3.1" \
  "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.1/nuclei_3.3.1_linux_${GOARCH}.zip"

_verify_or_reinstall subfinder "v2.6.6" \
  "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_${GOARCH}.zip"

_verify_or_reinstall httpx    "v1.6.6" \
  "https://github.com/projectdiscovery/httpx/releases/download/v1.6.6/httpx_1.6.6_linux_${GOARCH}.zip"

_verify_or_reinstall naabu    "v2.3.1" \
  "https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_${GOARCH}.zip"

# ── Nuclei-Templates ──────────────────────────────────────────────────────────
TEMPLATES_DIR="${HOME}/nuclei-templates"
STAMP_FILE="/tmp/.nuclei-updated"

# Update templates once per day or on first start
if [ ! -f "$STAMP_FILE" ] || [ "$(find "$STAMP_FILE" -mtime +1 2>/dev/null)" ]; then
    echo "[entrypoint] Aktualisiere Nuclei-Templates nach ${TEMPLATES_DIR}..."
    nuclei -update-templates -ud "${TEMPLATES_DIR}" 2>&1 || \
    nuclei -ut -ud "${TEMPLATES_DIR}" 2>&1 || \
    echo "[entrypoint] Template-Update fehlgeschlagen — fahre ohne aktuelle Templates fort"
    touch "$STAMP_FILE"
fi

# Verify templates were actually downloaded
TMPL_COUNT=$(find "${TEMPLATES_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
if [ "$TMPL_COUNT" -eq 0 ]; then
    echo "[entrypoint] WARNUNG: Keine Templates in ${TEMPLATES_DIR} — versuche nuclei ohne -ud..."
    nuclei -update-templates 2>&1 || true
fi

TMPL_COUNT=$(find "${TEMPLATES_DIR}" -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ' || echo 0)
echo "[entrypoint] Nuclei-Templates: ${TMPL_COUNT} .yaml Dateien in ${TEMPLATES_DIR}"

echo "[entrypoint] Starte Celery Worker..."
exec "$@"
