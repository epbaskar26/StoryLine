#!/usr/bin/env bash
# Inject synthetic cloud sign-in events into Elasticsearch so WatchMe can graph them.
# Cloud sign-ins (M365 / Entra ID / AWS / Okta) do not exist on a Windows endpoint; in production
# they come from the cloud audit logs via the Elastic or Splunk add-ons. This is a LAB test only.
#
# Run on the PC (not the VM):   bash tools/lab/inject-cloud-events.sh [ELASTIC_URL] [USER:PASS] [account]
# Defaults: http://localhost:9200  elastic:changeme  epbas
set -euo pipefail
ES="${1:-http://localhost:9200}"
AUTH="${2:-elastic:changeme}"
ACCT="${3:-epbas}"
IDX="cloud-signins-test"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
H2="$(date -u -d '-2 hours' +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u -v-2H +%Y-%m-%dT%H:%M:%S.000Z)"

post() {  # $1 = json doc
  curl -s -u "$AUTH" -H 'Content-Type: application/json' -X POST "$ES/$IDX/_doc" -d "$1" >/dev/null && echo "  indexed: $2"
}

echo "[*] Indexing synthetic cloud sign-ins for '$ACCT' into $ES/$IDX"

# Entra ID (Azure AD) interactive sign-in
post '{"@timestamp":"'"$H2"'","event":{"module":"azure","dataset":"azure.signinlogs","action":"Sign-in activity","outcome":"success","code":"cloud"},"user":{"name":"'"$ACCT"'"},"source":{"ip":"203.0.113.90"},"host":{"name":"entra-cloud"}}' "Entra ID sign-in"

# Microsoft 365 mailbox login
post '{"@timestamp":"'"$H2"'","event":{"module":"o365","dataset":"o365.audit","action":"UserLoggedIn","outcome":"success","code":"cloud"},"user":{"name":"'"$ACCT"'"},"source":{"ip":"203.0.113.90"},"host":{"name":"m365-cloud"}}' "Microsoft 365 login"

# Okta sign-in
post '{"@timestamp":"'"$NOW"'","event":{"module":"okta","dataset":"okta.system","action":"user.session.start","outcome":"success","code":"cloud"},"user":{"name":"'"$ACCT"'"},"source":{"ip":"198.51.100.7"},"host":{"name":"okta-cloud"}}' "Okta sign-in"

# AWS CloudTrail AssumeRole (suspicious cloud action)
post '{"@timestamp":"'"$NOW"'","event":{"module":"aws","dataset":"aws.cloudtrail","action":"AssumeRole","outcome":"success","code":"cloud"},"user":{"name":"'"$ACCT"'"},"source":{"ip":"45.154.255.89"},"host":{"name":"aws-cloud"},"signature":"AssumeRole"}' "AWS AssumeRole"

echo "[*] Point WatchMe at this index too, then reload:"
echo "    ELASTIC_INDEX=winlogbeat-*,$IDX   (in .env, then restart npm run dev)"
echo "    Open '$ACCT' - the cloud services appear as sign-in steps."
echo "[*] Remove afterwards:  curl -s -u $AUTH -X DELETE $ES/$IDX"
