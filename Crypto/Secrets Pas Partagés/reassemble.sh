#!/usr/bin/env bash
set -euo pipefail
PCAP="capture.pcap"
mkdir -p streams
rm -f streams/*.hex pqivc.json 2>/dev/null || true
echo "[*] Reassemble TCP streams…"
tshark -r "$PCAP" -T fields -e tcp.stream 2>/dev/null | awk 'NF' | sort -n | uniq | \
while read -r s; do
  out="streams/${PCAP##*/}.$s.hex"
  tshark -r "$PCAP" -q -z "follow,tcp,raw,$s" 2>/dev/null \
    | tr -d '\r\n' | tr 'A-F' 'a-f' | sed -E 's/[^0-9a-f]+//g' > "$out"
  [ -s "$out" ] || rm -f "$out"
done
echo "[i] built $(ls streams/*.hex 2>/dev/null | wc -l) streams"
