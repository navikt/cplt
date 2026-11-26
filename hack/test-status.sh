#!/usr/bin/env bash
# Self-check for hack/status.sh jq parsing, against hack/fixtures/status.
set -euo pipefail
cd "$(dirname "$0")"
out=$(./status.sh --fixture fixtures/status)
chk() { grep -Eq "$1" <<<"$out" || { echo "FAIL: $1"; echo "$out"; exit 1; }; }
chk '^1 +Starefossen +aaaaaaaa +SUCCESS +APPROVE +bbbbbbbb MISMATCH +1 +no +no +CLEAN'
chk '^2 +ext +cccccccc +none +none +- +0 +yes +yes +BLOCKED'
chk 'issue +#12 +ext .*reply [0-9]+d !'
chk 'PR +#2 +ext .*reply -[0-9]+d'
chk '^#10 '
! grep -Eq 'PR +#3' <<<"$out" || { echo 'FAIL: bot PR listed as external'; exit 1; }
./status.sh --fixture >/dev/null 2>&1 && { echo 'FAIL: --fixture without arg'; exit 1; }
! grep -Eq '^#11 |#13' <<<"$out" || { echo "FAIL: leaked #11/#13"; exit 1; }
echo ok
