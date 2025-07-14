#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_video.py – version compacte et robuste
"""
import hashlib, itertools, os, sys

CIPH      = "video_encrypted.mp4"
PLAIN_OUT = "L-is-dead_restored.mp4"
HDR_FIXED = b"\x00\x00\x00\x18ftypmp42"        # 12 octets garantis
KEY_LEN   = 4                                  # k0 k1 k2 k3

# ---------- F-fonction du chiffre original ----------
def func_key(block: bytes, key: bytes) -> bytes:
    return bytes((b * key[i % KEY_LEN]) & 0xff for i, b in enumerate(block))

# ---------- déchiffrement (inverse exact du 1er tour Feistel) ----------
def feistel_decrypt(cipher: bytes, key: bytes) -> bytes:
    mid = len(cipher) // 2
    R, CR = cipher[:mid], cipher[mid:]
    F     = func_key(R, key)
    L     = bytes(c ^ f for c, f in zip(CR, F))
    return L + R

# ---------- déduction de la clé à partir de 12 octets de clair connu ----------
def derive_key(R: bytes, CR: bytes) -> bytes:
    pools = [set(range(256)) for _ in range(KEY_LEN)]
    F = bytes(h ^ c for h, c in zip(HDR_FIXED, CR[:12]))
    for j, (r_byte, f_byte) in enumerate(zip(R[:12], F)):
        pools[j % KEY_LEN] = {k for k in pools[j % KEY_LEN]
                              if (r_byte * k) & 0xff == f_byte}
    # produit cartésien jusqu’à trouver LA clé qui redonne HDR_FIXED
    for candidate in itertools.product(*pools):
        key = bytes(candidate)
        if feistel_decrypt(R + CR, key)[:12] == HDR_FIXED:
            return key
    raise RuntimeError("Clé introuvable")

def main() -> None:
    if not os.path.isfile(CIPH):
        sys.exit(f"{CIPH} manquant")
    data = open(CIPH, "rb").read()
    key  = derive_key(data[:len(data)//2], data[len(data)//2:])
    print("Clé trouvée :", key, key.decode(errors='ignore'))
    plain = feistel_decrypt(data, key)
    if plain[-1] == 0 and (len(plain) - 1) & 1:
        plain = plain[:-1]                      # retire padding éventuel
    open(PLAIN_OUT, "wb").write(plain)
    digest = hashlib.sha256(plain).hexdigest()
    print("Flag :", f"SHLK{{{digest}}}")

if __name__ == "__main__":
    main()

