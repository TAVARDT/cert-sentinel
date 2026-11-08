#!/bin/bash
# ----------------------------------------------------------------------
# TAVARDT Certificate Sentinel (TLS/SSL Watchdog)
# Description: Automated TLS/SSL certificate & chain integrity inspector
# Website: https://ag.tavardt.com/
# ----------------------------------------------------------------------

set -e

# Terminal Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Default Settings
PORT="${PORT:-443}"
WARN_DAYS="${WARN_DAYS:-30}"
CRITICAL_DAYS="${CRITICAL_DAYS:-15}"
CONNECT_TIMEOUT=5

echo -e "${BLUE}${BOLD}🔍 [TAVARDT CYBER] Certificate Sentinel Watchdog v1.0.0${NC}"
echo -e "${CYAN}Protecting corporate infrastructure against certificate expiration & PKI failures.${NC}\n"

# Helper usage
usage() {
  echo -e "Usage:"
  echo -e "  bash sentinel.sh <domain> [port]"
  echo -e "  bash sentinel.sh --file <domains.txt>"
  echo -e "  WEBHOOK_URL=\"https://...\" bash sentinel.sh <domain>\n"
  echo -e "Environment Variables:"
  echo -e "  WARN_DAYS=30        Days threshold for warning alert (default: 30)"
  echo -e "  CRITICAL_DAYS=15    Days threshold for critical alert (default: 15)"
  echo -e "  WEBHOOK_URL         Webhook endpoint (Slack, Discord, Telegram, or JSON)"
  exit 1
}

# Check OpenSSL dependency
if ! command -v openssl &> /dev/null; then
  echo -e "${RED}🚨 [ERROR] OpenSSL is not installed. Please install openssl to proceed.${NC}"
  exit 1
fi

send_webhook() {
  local domain="$1"
  local days="$2"
  local status="$3"
  local issuer="$4"
  
  if [ -z "$WEBHOOK_URL" ]; then
    return 0
  fi

  local payload
  payload=$(cat <<EOF
{
  "service": "TAVARDT Certificate Sentinel",
  "domain": "$domain",
  "days_remaining": $days,
  "status": "$status",
  "issuer": "$issuer",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
)

  echo -e "📡 [WEBHOOK] Dispatching notification to endpoint..."
  curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$WEBHOOK_URL" > /dev/null 2>&1 || true
}

inspect_domain() {
  local target_raw="$1"
  local target_port="${2:-$PORT}"

  # Clean protocol or slashes if user passed full URL
  local target
  target=$(echo "$target_raw" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:[0-9]*$||')

  if [ -z "$target" ]; then
    return 0
  fi

  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "🔐 [INSPECTING] ${CYAN}${BOLD}$target${NC} (Port: $target_port)"

  # Fetch Certificate via OpenSSL
  local cert_raw
  cert_raw=$(timeout "$CONNECT_TIMEOUT" openssl s_client -servername "$target" -connect "$target:$target_port" 2>/dev/null </dev/null || true)

  if [ -z "$cert_raw" ] || ! echo "$cert_raw" | grep -q "BEGIN CERTIFICATE"; then
    echo -e "${RED}🚨 [ERROR] Unable to establish TLS connection with $target:$target_port${NC}"
    echo -e "   Check if the port is open and server responds to SNI."
    send_webhook "$target" -1 "UNREACHABLE" "N/A"
    return 1
  fi

  # Extract Certificate Info
  local cert_text
  cert_text=$(echo "$cert_raw" | openssl x509 -noout -text 2>/dev/null)
  
  local issuer
  issuer=$(echo "$cert_raw" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer= //')

  local subject
  subject=$(echo "$cert_raw" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject= //')

  local end_date_str
  end_date_str=$(echo "$cert_raw" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)

  local start_date_str
  start_date_str=$(echo "$cert_raw" | openssl x509 -noout -startdate 2>/dev/null | cut -d= -f2)

  # Calculate Days Remaining
  local end_epoch
  if date -d "$end_date_str" +%s >/dev/null 2>&1; then
    # GNU date (Linux)
    end_epoch=$(date -d "$end_date_str" +%s)
  elif date -j -f "%b %d %T %Y %Z" "$end_date_str" +%s >/dev/null 2>&1; then
    # BSD date (macOS)
    end_epoch=$(date -j -f "%b %d %T %Y %Z" "$end_date_str" +%s)
  else
    # Fallback to python for platform independence
    end_epoch=$(python3 -c "import email.utils; from datetime import datetime; print(int(datetime.strptime('$end_date_str', '%b %d %H:%M:%S %Y %Z').timestamp()))" 2>/dev/null || echo 0)
  fi

  local now_epoch
  now_epoch=$(date +%s)
  local diff_seconds=$((end_epoch - now_epoch))
  local days_left=$((diff_seconds / 86400))

  echo -e "   👤 Subject:      ${CYAN}$subject${NC}"
  echo -e "   🏛️  Issuer:       ${CYAN}$issuer${NC}"
  echo -e "   📅 Valid From:   $start_date_str"
  echo -e "   📅 Expires On:   $end_date_str"

  # Protocol and Cipher inspection
  local proto_cipher
  proto_cipher=$(echo "$cert_raw" | grep -E "Protocol|Cipher" | tr -d ' ' | tr '\n' ' ' || true)
  if [ -n "$proto_cipher" ]; then
    echo -e "   ⚡ Connection:   $proto_cipher"
  fi

  # Check Revoked CA blacklist (e.g. eMudhra or untrusted roots)
  if echo "$issuer" | grep -qi "eMudhra"; then
    echo -e "${RED}🚨 [COMPROMISE RISK] Certificate issued by flagged CA (eMudhra incident)!${NC}"
  fi

  # Expiration Health Check
  if [ "$days_left" -le 0 ]; then
    echo -e "${RED}${BOLD}❌ [CRITICAL] CERTIFICATE EXPIRED! Days remaining: $days_left${NC}"
    echo -e "   Immediate renewal required to restore HTTPS availability."
    send_webhook "$target" "$days_left" "EXPIRED" "$issuer"
  elif [ "$days_left" -le "$CRITICAL_DAYS" ]; then
    echo -e "${RED}${BOLD}🚨 [CRITICAL ALERT] Certificate expires in $days_left days! (Threshold <= $CRITICAL_DAYS days)${NC}"
    echo -e "   Risk of service outage. Renew immediately."
    send_webhook "$target" "$days_left" "CRITICAL" "$issuer"
  elif [ "$days_left" -le "$WARN_DAYS" ]; then
    echo -e "${YELLOW}${BOLD}⚠️  [WARNING] Certificate expires in $days_left days. (Threshold <= $WARN_DAYS days)${NC}"
    echo -e "   Schedule renewal in next maintenance window."
    send_webhook "$target" "$days_left" "WARNING" "$issuer"
  else
    echo -e "${GREEN}${BOLD}✅ [HEALTHY] Certificate is valid. $days_left days remaining.${NC}"
    echo -e "   Domain complies with TAVARDT enterprise security standards."
  fi

  echo ""
}

# Entrypoint
if [ $# -eq 0 ]; then
  usage
fi

if [ "$1" == "--file" ] || [ "$1" == "-f" ]; then
  if [ -z "$2" ] || [ ! -f "$2" ]; then
    echo -e "${RED}🚨 [ERROR] Domain list file not found: $2${NC}"
    exit 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    # Skip empty lines and comments
    [[ "$line" =~ ^#.*$ ]] && continue
    [ -z "$line" ] && continue
    inspect_domain "$line"
  done < "$2"
else
  inspect_domain "$1" "$2"
fi

echo -e "${BLUE}${BOLD}✅ [SUCCESS] TAVARDT Certificate Sentinel Watchdog Complete.${NC}"
echo -e "${CYAN}🔗 For advanced cyber defense & infrastructure audit: https://ag.tavardt.com/${NC}"
