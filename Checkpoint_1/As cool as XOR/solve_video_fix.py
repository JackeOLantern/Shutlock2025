#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_video_fix.py – même objectif, même résultat,
mais on garde la mécanique « pools » et la validation progressive.
"""
import hashlib, itertools, os, sys

CIPH      = "video_encrypted.mp4"
PLAIN_OUT = "L-is-dead_restored.mp4"
HDR0      = b"\x00\x00\x00\x18ftyp"    # 8 octets sûrs
HDR1      = b"mp42"                    # 4 octets suivants

def func_key(buf: bytes, key: bytes) -> bytes:
    return bytes((b * key[i & 3]) & 0xff for i, b in enumerate(buf))

def derive_key(R: bytes, CR: bytes) -> bytes:
    F = bytes(l ^ c for l, c in zip(HDR0, CR[:8]))
    pools = [set() for _ in range(4)]
    for j in range(8):
        idx = j & 3
        pools[idx].update(k for k in range(256) if (R[j] * k) & 0xff == F[j])
    for k0, k1, k2, k3 in itertools.product(*pools):
        key = bytes([k0, k1, k2, k3])
        # vérifie HDR0+HDR1
        L_test = bytes(c ^ f for c, f in zip(CR[:12], func_key(R[:12], key)))
        if L_test.startswith(HDR0 + HDR1):
            return key
    raise RuntimeError("Aucune clé valide")

def feistel_decrypt(cipher: bytes, key: bytes) -> bytes:
    half = len(cipher) // 2
    R, CR = cipher[:half], cipher[half:]
    L = bytes(c ^ f for c, f in zip(CR, func_key(R, key)))
    return L + R

def main():
    if not os.path.exists(CIPH):
        sys.exit("Fichier chiffré absent")
    with open(CIPH, "rb") as f:
        cipher = f.read()
    half = len(cipher)//2
    key = derive_key(cipher[:half], cipher[half:])
    print("✅ clé :", key, key.decode(errors='ignore'))
    plain = feistel_decrypt(cipher, key)
    if plain[-1] == 0 and (len(plain)-1) & 1:
        plain = plain[:-1]
    with open(PLAIN_OUT, "wb") as f:
        f.write(plain)
    sha = hashlib.sha256(plain).hexdigest()
    print("🏁  Flag : SHLK{" + sha + "}")

if __name__ == "__main__":
    main()
