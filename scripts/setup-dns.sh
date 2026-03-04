#!/bin/bash
# Create DNS record for secid.cloudsecurityalliance.org
#
# Prerequisites: CLOUDFLARE_API_TOKEN env var with Zone:Edit permission
# (or use wrangler's stored OAuth token via the API)
#
# This creates a proxied AAAA record pointing to 100:: (stub address).
# The actual traffic is handled by the Workers route, not this address.

set -euo pipefail

ZONE_ID="113bb8004441490558a7ce8b4b611cc1"
RECORD_NAME="secid.cloudsecurityalliance.org"
RECORD_TYPE="AAAA"
RECORD_CONTENT="100::"

# Use CLOUDFLARE_API_TOKEN if set, otherwise try to extract from wrangler's OAuth config
if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "CLOUDFLARE_API_TOKEN not set. Checking wrangler OAuth config..."
  # wrangler stores OAuth tokens in ~/.wrangler/config/default.toml or similar
  WRANGLER_CONFIG="$HOME/.config/.wrangler/config/default.toml"
  if [ -f "$WRANGLER_CONFIG" ]; then
    TOKEN=$(grep -oP 'oauth_token\s*=\s*"\K[^"]+' "$WRANGLER_CONFIG" 2>/dev/null || true)
    if [ -n "$TOKEN" ]; then
      export CLOUDFLARE_API_TOKEN="$TOKEN"
      echo "Using token from wrangler config."
    fi
  fi
fi

if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "Error: No API token found. Set CLOUDFLARE_API_TOKEN or log in with 'npx wrangler login'."
  exit 1
fi

echo "Checking if DNS record already exists..."
EXISTING=$(curl -s -X GET \
  "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=${RECORD_TYPE}&name=${RECORD_NAME}" \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  -H "Content-Type: application/json")

RECORD_COUNT=$(echo "$EXISTING" | python3 -c "import sys,json; print(json.load(sys.stdin)['result_info']['count'])" 2>/dev/null || echo "0")

if [ "$RECORD_COUNT" != "0" ]; then
  RECORD_ID=$(echo "$EXISTING" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'][0]['id'])")
  echo "DNS record already exists (ID: $RECORD_ID). Updating..."
  RESPONSE=$(curl -s -X PUT \
    "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${RECORD_ID}" \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{
      \"type\": \"${RECORD_TYPE}\",
      \"name\": \"${RECORD_NAME}\",
      \"content\": \"${RECORD_CONTENT}\",
      \"proxied\": true,
      \"ttl\": 1
    }")
else
  echo "Creating DNS record: ${RECORD_NAME} ${RECORD_TYPE} ${RECORD_CONTENT} (proxied)..."
  RESPONSE=$(curl -s -X POST \
    "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
    -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{
      \"type\": \"${RECORD_TYPE}\",
      \"name\": \"${RECORD_NAME}\",
      \"content\": \"${RECORD_CONTENT}\",
      \"proxied\": true,
      \"ttl\": 1
    }")
fi

SUCCESS=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['success'])" 2>/dev/null || echo "false")

if [ "$SUCCESS" = "True" ]; then
  echo "Done. DNS record for ${RECORD_NAME} is active (proxied via Cloudflare)."
else
  echo "Failed. API response:"
  echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"
  exit 1
fi
