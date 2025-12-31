#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Extrait automatiquement :
  • P.bin  = 1er point EC client→serveur
  • Q.bin  = 1er point EC serveur→client
  • ct.bin = IV (16) + ciphertext (48) juste après Q
Fonctionne avec points compressés ET non-compressés.
"""
import sys, struct, os
from scapy.all import rdpcap, TCP, IP

PCAP = sys.argv[1]

pkts = rdpcap(PCAP)

cli, srv = None, None
P_raw = Q_raw = ct = None

for p in pkts:
    if not p.haslayer(TCP): continue
    pay = bytes(p[TCP].payload)
    if len(pay) in (33,65) and pay[0] in (2,3,4):         # point EC
        if cli is None:
            cli, srv = p[IP].src, p[IP].dst          # mémorise sens
        if p[IP].src == cli and P_raw is None:
            P_raw = pay
        elif p[IP].src == srv and Q_raw is None:
            Q_raw = pay
            continue
    # récupère IV+ciphertext juste APRES Q
    if Q_raw and ct is None and len(pay) == 64:
        ct = pay

    if P_raw and Q_raw and ct:
        break

assert P_raw and Q_raw and ct, "Impossible de tout extraire"

open("P.bin","wb").write(P_raw)
open("Q.bin","wb").write(Q_raw)
open("ct.bin","wb").write(ct)
print("[✓] P.bin / Q.bin / ct.bin écrits.")

print("Relance ensuite :  ./solve_dhutlock.py", sys.argv[2] if len(sys.argv)>2 else "<borne_hex>")
