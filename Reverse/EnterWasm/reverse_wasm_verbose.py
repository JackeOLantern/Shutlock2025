#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reverse_wasm.py
----------------
Récupère et vérifie le mot de passe attendu par encode.wasm sans dépendance externe.

Contexte (fonction check reconstituée):
  - Mémoire initiale : mem[0..7] = password (8 octets)
                       mem[8..15] = B (8 octets du segment data 1)
  - Pour i = 0..7:
        a = mem[i]
        b = B[i]
        x = a ^ b
        mem[i] = x               (l'unique effet observable du i32.store non aligné)
        n = x & 31
        si (x & 1) == 0 : ROTR32(n) sur dword0 (mem[0..3]) et dword1 (mem[4..7])
        sinon            ROTL32(n) sur ces deux dwords
  - À la fin : succès si mem[0..7] == A (2ᵉ segment data de 8 octets)

Inversion (reverse) i = 7 → 0 :
  On part de l'état final A (après la rotation de i=7).
  Pour chaque i :
      On essaie x=0..255 :
          - Dé-rotater (inverse exacte de la rotation faite si x avait été utilisé)
          - L'état obtenu est l'état 'post-store / pré-rotation'; on exige mem[i] == x.
          - On en déduit a = x ^ B[i] (l'octet original avant XOR)
          - On reconstruit l'état 'avant itération i' en remplaçant mem[i] = a
          - Validation : rejouer (store + rotation) → doit retomber sur l'état de départ
      Une fois trouvé : on continue avec i-1.
  À la fin, l'état courant est exactement les octets initiaux du mot de passe.

Le dernier état avant i=0 ⇒ password = "pureWASM".
"""

import sys
import argparse
from typing import Tuple, List

MAGIC = b'\x00asm'
DATA_SEC_ID = 11

# --------------------------------------------------------------------
# 1. Lecture / parsing minimal du WASM (section Data + segments actifs)
# --------------------------------------------------------------------
def read_u32_leb(buf: bytes, off: int) -> Tuple[int, int]:
    """Lit un entier LEB128 non signé à partir de l’offset off."""
    res = 0
    shift = 0
    p = off
    while True:
        b = buf[p]; p += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, p

def iter_sections(blob: bytes):
    """Itère sur (section_id, payload_bytes). Saute l'entête de 8 octets."""
    p = 8
    while p < len(blob):
        sid = blob[p]; p += 1
        size, np = read_u32_leb(blob, p)
        payload = blob[np:np+size]
        yield sid, payload
        p = np + size

def extract_segments(blob: bytes) -> List[Tuple[int, bytes]]:
    """
    Retourne la liste des segments (offset, data) de la section Data
    ne gardant que ceux de longueur 8 (les deux constants qui nous intéressent).
    """
    segs = []
    for sid, payload in iter_sections(blob):
        if sid == DATA_SEC_ID:  # section "data" = 11
            q = 0
            count, q = read_u32_leb(payload, q)
            for _ in range(count):
                mode = payload[q]; q += 1
                if mode != 0:
                    raise ValueError("Segment passif / mode non géré.")
                if payload[q] != 0x41:  # i32.const
                    raise ValueError("Expression d'offset inattendue.")
                q += 1
                off, q = read_u32_leb(payload, q)
                if payload[q] != 0x0B:  # end
                    raise ValueError("Fin d'expression (0x0B) attendue.")
                q += 1
                size, q = read_u32_leb(payload, q)
                data = payload[q:q+size]; q += size
                if len(data) == 8:
                    segs.append((off, data))
    return sorted(segs, key=lambda x: x[0])

# --------------------------------------------------------------------
# 2. Primitives de rotation 32 bits
# --------------------------------------------------------------------
def rotl32(v: int, n: int) -> int:
    n &= 31
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))

def rotr32(v: int, n: int) -> int:
    n &= 31
    return (v >> n) | ((v << (32 - n)) & 0xFFFFFFFF)

# --------------------------------------------------------------------
# 3. Helpers d’affichage
# --------------------------------------------------------------------
def ascii_vis(b: bytes) -> str:
    """Affiche '.' pour octets non imprimables."""
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b)

def hex_bytes(b: bytes) -> str:
    return b.hex()

# --------------------------------------------------------------------
# 4. Simulation forward fidèle du modèle minimal
# --------------------------------------------------------------------
def forward_check(pwd: bytes, B: bytes, A: bytes, trace=False) -> bool:
    """
    Applique l'algorithme 'check' reconstitué et compare le résultat final à A.
    """
    mem = bytearray(16)
    mem[0:8] = pwd
    mem[8:16] = B

    if trace:
        print("=== FORWARD (simulation) ===")
        print(f"INIT  mem[0..7]={mem[0:8].hex()} | {ascii_vis(mem[0:8])}")

    for i in range(8):
        a = mem[i]
        b = mem[8 + i]
        x = a ^ b                 # XOR déterministe
        mem[i] = x                # effet observable du store
        n = x & 31                # magnitude de rotation
        w0 = int.from_bytes(mem[0:4], 'little')
        w1 = int.from_bytes(mem[4:8], 'little')
        if (x & 1) == 0:          # bit de parité décide sens
            w0 = rotr32(w0, n); w1 = rotr32(w1, n)
            direction = "ROTR"
        else:
            w0 = rotl32(w0, n); w1 = rotl32(w1, n)
            direction = "ROTL"
        mem[0:4] = w0.to_bytes(4, 'little')
        mem[4:8] = w1.to_bytes(4, 'little')

        if trace:
            print(f"i={i} | a={a:02x} B[i]={b:02x} x=a^B={x:02x} n={n:2d} {direction:4s} "
                  f"=> {mem[0:8].hex()} | {ascii_vis(mem[0:8])}")

    ok = (mem[0:8] == A)
    if trace:
        print(f"FINAL mem[0..7]={mem[0:8].hex()} target={A.hex()} => {'OK' if ok else 'KO'}")
    return ok

# --------------------------------------------------------------------
# 5. Inversion (reverse) – reconstruction du mot de passe étape par étape
# --------------------------------------------------------------------
def reverse_password(B: bytes, A: bytes, trace=False) -> bytes:
    """
    Reconstruit le mot de passe original à partir de l'état final A.
    Important : l'état 'state_after' à la fin de la boucle = mot de passe.
    """
    state_after = bytearray(A)  # état courant "après rotation de l'itération i"
    if trace:
        print("=== REVERSE (inversion) ===")
        print(f"État final (A) = {state_after.hex()} | {ascii_vis(state_after)}")

    # i = 7 → 0
    for i in reversed(range(8)):
        found = False
        # On essaie chaque x possible (0..255)
        for x in range(256):
            n = x & 31
            forward_would_rotr = ((x & 1) == 0)  # si vrai, forward a appliqué ROTR

            # Inverse de la rotation :
            w0 = int.from_bytes(state_after[0:4], 'little')
            w1 = int.from_bytes(state_after[4:8], 'little')
            if forward_would_rotr:
                # Forward: ROTR => inverse = ROTL
                w0i = rotl32(w0, n); w1i = rotl32(w1, n)
                inv_dir = "ROTR->inv=ROTL"
            else:
                # Forward: ROTL => inverse = ROTR
                w0i = rotr32(w0, n); w1i = rotr32(w1, n)
                inv_dir = "ROTL->inv=ROTR"

            pre_rot = bytearray(8)
            pre_rot[0:4] = w0i.to_bytes(4, 'little')
            pre_rot[4:8] = w1i.to_bytes(4, 'little')

            # Condition post-store (avant rotation forward) : mem[i] == x
            if pre_rot[i] != x:
                continue

            # Revenir avant le XOR : a = x ^ B[i]
            a = x ^ B[i]

            # État avant l'itération i (avant XOR/store/rotation)
            before_iter = bytearray(pre_rot)
            before_iter[i] = a

            # Validation locale : rejouer EXACTEMENT l'itération i pour retomber sur state_after
            test = bytearray(before_iter)
            x2 = test[i] ^ B[i]            # devrait redonner x
            if x2 != x:
                continue
            test[i] = x2
            n2 = x2 & 31
            w0t = int.from_bytes(test[0:4], 'little')
            w1t = int.from_bytes(test[4:8], 'little')
            if (x2 & 1) == 0:
                w0t = rotr32(w0t, n2); w1t = rotr32(w1t, n2)
            else:
                w0t = rotl32(w0t, n2); w1t = rotl32(w1t, n2)
            test[0:4] = w0t.to_bytes(4, 'little')
            test[4:8] = w1t.to_bytes(4, 'little')

            if test != state_after:
                continue  # hypothèse incohérente globalement

            # Succès pour cet i
            if trace:
                print(f"i={i} | x={x:02x} a={a:02x} n={n:2d} {inv_dir:15s} "
                      f"pre_rot={pre_rot.hex()} before_iter={before_iter.hex()}  "
                      f"('{ascii_vis(before_iter)}')")
            state_after = before_iter
            found = True
            break

        if not found:
            raise RuntimeError(f"Inversion échouée à i={i} (fichier inattendu ?)")

    # À ce stade, state_after = état avant i=0 = mot de passe original
    return bytes(state_after)

# --------------------------------------------------------------------
# 6. Explication pédagogique optionnelle
# --------------------------------------------------------------------
def print_explanation():
    print(r"""
[EXPLICATION]
Le binaire encode.wasm contient deux segments de 8 octets :
  B : clé XOR
  A : état final attendu après 8 itérations de transformations.

Transformations forward (i = 0..7):
  1. x = mem[i] ^ B[i]
  2. mem[i] = x
  3. n = x & 31
  4. si x pair  -> rotation droite (ROTR32) de n bits des deux dwords (0..3) et (4..7)
     si x impair -> rotation gauche (ROTL32) idem
Succès si mem[0..7] == A.

Reverse (i = 7..0):
  - On suppose une valeur x candidate.
  - On applique la rotation inverse (ROTL si forward était ROTR, sinon ROTR).
  - On exige que l'octet i du buffer inversé soit x (cohérence post-store).
  - On calcule a = x ^ B[i] (valeur avant XOR).
  - On remplace l'octet i par a (état avant itération i).
  - On re-simule juste cette itération pour vérifier qu'on retrouve l'état courant.
  - On passe à l'itération précédente.

Au final, l'état reconstruit est le mot de passe initial.
""".strip())

# --------------------------------------------------------------------
# 7. Programme principal
# --------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Reverse du mot de passe encode.wasm.")
    parser.add_argument("--file", default="encode.wasm", help="Fichier WASM (défaut: encode.wasm)")
    parser.add_argument("--trace-reverse", action="store_true", help="Afficher chaque étape d'inversion.")
    parser.add_argument("--trace-forward", action="store_true", help="Afficher chaque étape forward.")
    parser.add_argument("--explain", action="store_true", help="Afficher l'explication du modèle.")
    parser.add_argument("--hex", action="store_true", help="N'afficher que le mot de passe en hex (sortie compacte).")
    args = parser.parse_args()

    if args.explain:
        print_explanation()
        print()

    # Lecture du binaire
    try:
        blob = open(args.file, "rb").read()
    except OSError as e:
        print("Erreur ouverture fichier:", e)
        sys.exit(1)

    if blob[:4] != MAGIC:
        print("Fichier invalide (entête WASM manquante).")
        sys.exit(1)

    # Extraction des deux segments de 8 octets
    segs = extract_segments(blob)
    eight = [s for s in segs if len(s[1]) == 8]
    if len(eight) < 2:
        print("Segments 8 octets insuffisants.")
        for off, data in segs:
            print(f"@{off} ({len(data)}): {data.hex()}")
        sys.exit(1)

    B = eight[0][1]
    A = eight[1][1]

    if not args.hex:
        print(f"[+] Segment B (offset {eight[0][0]}) = {B.hex()} | {ascii_vis(B)}")
        print(f"[+] Segment A (offset {eight[1][0]}) = {A.hex()} | {ascii_vis(A)}")

    # Inversion
    pwd = reverse_password(B, A, trace=args.trace_reverse)

    # Vérification
    ok = forward_check(pwd, B, A, trace=args.trace_forward)

    if args.hex:
        print(pwd.hex())
    else:
        print()
        print(f"Mot de passe: {pwd.decode('latin1')} {pwd.hex()}")
        print(f"Forward OK ? {ok}")
        if ok:
            print(f"Flag: SHLK{{{pwd.decode('latin1')}}}")

if __name__ == "__main__":
    main()
