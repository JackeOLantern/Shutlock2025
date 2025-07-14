#!/usr/bin/env python3
"""
solve_video_final.py
--------------------
Déchiffre video_encrypted.mp4 (produit par as_cool_as_xor.py),
recrée L-is-dead.mp4, calcule son SHA-256 et imprime le flag
au format : SHLK{…}

Usage :  python3 solve_video_final.py
"""

import os, sys, hashlib, itertools

# --- constantes ---
CIPH = "video_encrypted.mp4"
PLAIN_OUT = "L-is-dead_restored.mp4"
HDR0 = b"\x00\x00\x00\x18ftyp"      # 8 octets fixes d’un MP4
HDR1 = b"mp42"                      # major_brand le + courant

# --- F-fonction identique à celle du script original ---
def func_key(block: bytes, key: bytes) -> bytes:
    return bytes((b * key[i % 4]) & 0xFF for i, b in enumerate(block))

# --- déchiffrement (1 tour Feistel : récupérer L, R) ---
def feistel_decrypt(cipher: bytes, key: bytes) -> bytes:
    if len(cipher) & 1:
        raise ValueError("Longueur chiffré impaire – anormal")
    mid = len(cipher) // 2
    R   = cipher[:mid]          # moitié gauche du chiffré = R0
    CR  = cipher[mid:]          # moitié droite = L0 ⊕ F(R0)
    F   = func_key(R, key)
    L   = bytes(c ^ f for c, f in zip(CR, F))
    return L + R                # L0 ∥ R0

# --- dérivation automatique de la clé ---
def derive_key(R: bytes, CR: bytes) -> bytes:
    """Retourne la (les) clé(s) candidate(s) sous forme de liste de bytes."""
    # calcul des 8 premiers octets de F = L ⊕ CR
    F = bytes(l ^ c for l, c in zip(HDR0, CR[:8]))

    # pour chaque résidu i mod 4, on garde toutes les k telles que (Rj * k) % 256 == Fj
    pools = [set(range(256)) for _ in range(4)]
    for j in range(8):           # 8 contraintes indépendantes
        idx = j % 4
        pools[idx] = {k for k in pools[idx] if (R[j] * k) & 0xFF == F[j]}
        if not pools[idx]:
            raise RuntimeError(f"Aucune clé possible pour l’octet {idx}")
    # produit cartésien des pools
    for k0, k1, k2, k3 in itertools.product(*pools):
        key = bytes([k0, k1, k2, k3])
        # validation rapide : doit refaire hdr complet
        L_test = bytes(c ^ f for c, f in zip(CR[:12], func_key(R[:12], key)))
        if L_test[:8] == HDR0 and L_test[8:12] == HDR1:
            return key          # trouvée
    raise RuntimeError("clé introuvable ; pools = " + repr(pools))

# --- programme principal ---
def main():
    if not os.path.isfile(CIPH):
        sys.exit(f"❌  Fichier {CIPH} introuvable")

    # lecture du chiffré et séparation des moitiés
    size = os.path.getsize(CIPH)
    mid  = size // 2
    with open(CIPH, "rb") as f:
        R  = f.read(mid)        # première moitié
        CR = f.read(mid)        # seconde moitié

    key = derive_key(R, CR)
    print(f"🔑  Clé retrouvée : {key}  (ASCII : {key.decode(errors='ignore')})")

    # déchiffrer l’intégralité
    with open(CIPH, "rb") as f:
        cipher = f.read()
    plain = feistel_decrypt(cipher, key)

    # retirer le padding éventuel (ajouté si longueur impaire)
    if plain[-1] == 0 and (len(plain) - 1) & 1:
        plain = plain[:-1]

    # écriture + SHA-256
    with open(PLAIN_OUT, "wb") as f:
        f.write(plain)
    digest = hashlib.sha256(plain).hexdigest()
    print(f"✅  Fichier restauré → {PLAIN_OUT}")
    print(f"🏁  Flag : SHLK{{{digest}}}")

if __name__ == "__main__":
    main()
