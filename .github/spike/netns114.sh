#!/usr/bin/env bash
# SPIKE #114 (do not merge): probe the netns bridge against a real cplt build.
set -u
B="$PWD/target/release/cplt"
H=$(mktemp -d "$HOME/spike.XXXX"); mkdir -p "$H/.opencode/bin" "$H/work/proj" "$H/.config/opencode"
echo '{}' > "$H/.config/opencode/opencode.json"
git -C "$H/work/proj" init -q
printf '#!/bin/sh\n[ "$1" = --version ] && { echo opencode v2.0.24; exit 0; }\nexec /bin/sh -c "$1"\n' > "$H/.opencode/bin/opencode"
chmod +x "$H/.opencode/bin/opencode"
run() { (cd "$H/work/proj" && HOME="$H" PATH="$H/.opencode/bin:/usr/bin:/bin" "$B" --yes --agent opencode --use-bubblewrap -- "$1"); }

python3 -m http.server 18765 --bind 127.0.0.1 >/dev/null 2>&1 & HTTP=$!
sleep 1
PROBE='
echo "LINKS: $(ip -br link 2>&1 | tr "\n" ";")"
echo "ADDRS: $(ip -br addr 2>&1 | tr "\n" ";")"
echo "PROXY=$HTTPS_PROXY"
curl -sS -m10 -o /dev/null -w "CONNECT_HTTP_CODE %{http_code}\n" https://github.com/ 2>&1
curl --noproxy "*" -sS -m5 -o /dev/null https://140.82.112.3/ 2>&1 && echo DIRECT_TCP=OPEN || echo DIRECT_TCP=BLOCKED
curl --noproxy "*" -sS -m5 -o /dev/null http://127.0.0.1:18765/ 2>&1 && echo HOST_LOOPBACK=OPEN || echo HOST_LOOPBACK=BLOCKED
getent hosts example.com >/dev/null && echo DNS=OPEN || echo DNS=BLOCKED
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(b\"x\",(\"8.8.8.8\",53));print(\"UDP53_SEND=OK\")" 2>&1 | tail -1
ps -eo pid,ppid,comm | tr "\n" ";"; echo
'
for mode in baseline netns; do
  echo "===== $mode probe ====="
  if [ $mode = netns ]; then export CPLT_SPIKE_NETNS=1; else unset CPLT_SPIKE_NETNS; fi
  run "$PROBE" 2>&1 | grep -v '^\s*$' | tail -40
  echo "===== $mode timing (20 x 'true', ms) ====="
  ts=()
  for i in $(seq 20); do
    s=$(date +%s%N); run true >/dev/null 2>&1; e=$(date +%s%N); ts+=($(( (e-s)/1000000 )))
  done
  echo "${ts[*]}" | tr ' ' '\n' | sort -n | awk '{a[NR]=$1} END{print "min",a[1],"median",a[int((NR+1)/2)],"max",a[NR]}'
done

echo "===== teardown: normal exit ====="
export CPLT_SPIKE_NETNS=1
run true >/dev/null 2>&1; sleep 1
pgrep -af "$B" && echo LEAK_NORMAL=YES || echo LEAK_NORMAL=NO
echo "===== teardown: SIGKILL cplt parent mid-session ====="
(cd "$H/work/proj" && HOME="$H" PATH="$H/.opencode/bin:/usr/bin:/bin" exec "$B" --yes --agent opencode --use-bubblewrap -- "sleep 30") >/dev/null 2>&1 &
P=$!; sleep 3
echo "during: $(pgrep -af "$B" | wc -l) cplt procs; tree:"; ps -eo pid,ppid,comm --forest | grep -E "cplt|bwrap|sleep" | grep -v grep
kill -9 $P; sleep 2
pgrep -af "$B" && echo LEAK_KILL=YES || echo LEAK_KILL=NO
pgrep -a sleep | grep 30 && echo AGENT_SURVIVED=YES || echo AGENT_SURVIVED=NO
kill $HTTP
