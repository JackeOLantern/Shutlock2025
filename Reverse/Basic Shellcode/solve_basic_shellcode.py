#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
solve_basic_shellcode_final.py
───────────────────────────────
Reproduction exacte de la logique du crackme + vérifications.

Étapes :
 1) Constantes KEY (16o) & SECRET (32o) extraites de check().
 2) Reconstruction du buffer attendu (après permutation) par XOR.
 3) Inversion de la permutation j = (7*i) mod 32 -> i = (23*j) mod 32.
 4) Simulation fidèle des 4 appels à check().
 5) Vérifications internes + affichage du flag à saisir dans le binaire.

"""

from __future__ import annotations

# 1. Constantes
KEY_HEX = "79 30 55 46 6f 75 4e 64 6d 59 78 30 72 4b 45 79"
SECRET_HEX = (
    "2a 43 3b 12 29 44 2d 0e 5f 30 26 08 2d 21 02 37"
    " 1a 6a 1d 55 32 12 11 5f 3c 36 68 49 09 26 0b 1c"
)

KEY    = bytes.fromhex(KEY_HEX)
SECRET = bytes.fromhex(SECRET_HEX)

assert len(KEY) == 16, len(KEY)
assert len(SECRET) == 32, len(SECRET)

# 2. Reconstruction du buffer attendu par check() (après permutation)
def build_expected_buffer() -> bytes:
    out = bytearray()
    for blk in range(4):          # p = 1..4 (blocs de 8 octets)
        for i in range(8):
            out.append(SECRET[8*blk + i] ^ KEY[4*blk + (i & 3)])
    return bytes(out)

EXPECTED_BUFFER = build_expected_buffer()
assert len(EXPECTED_BUFFER) == 32

# 3. Permutation & inverse (shellcode)
#    j = (7 * i) % 32         (i = index dans l'input utilisateur, j = index vu par check)
#    inverse : i = (23 * j) % 32 car 7 * 23 ≡ 1 (mod 32)
def apply_permutation(user_input: str) -> bytes:
    assert len(user_input) == 32
    buf = bytearray(32)
    raw = user_input.encode('latin1')  # 1 byte par char attendu
    for i, ch_val in enumerate(raw):
        j = (7 * i) % 32
        buf[j] = ch_val
    return bytes(buf)

def inverse_permutation(buffer_bytes: bytes) -> str:
    assert len(buffer_bytes) == 32
    chars = ['?'] * 32
    for j, b in enumerate(buffer_bytes):
        i = (23 * j) % 32
        # b est un int (car on itère directement sur bytes) -> safe pour chr()
        chars[i] = chr(b)
    return "".join(chars)

# 4. Simulation de check()
def check_block(block: bytes, p: int) -> bool:
    if len(block) != 8 or not (1 <= p <= 4):
        return False
    base_k = 4 * (p - 1)
    base_s = 8 * (p - 1)
    for i in range(8):
        if (block[i] ^ KEY[base_k + (i & 3)]) != SECRET[base_s + i]:
            return False
    return True

def run_full_check(permuted: bytes) -> bool:
    if len(permuted) != 32:
        return False
    return all(check_block(permuted[8*(p-1):8*p], p) for p in range(1, 5))

# 5. Reconstituer le flag utilisateur
user_flag = inverse_permutation(EXPECTED_BUFFER)
permuted_flag = apply_permutation(user_flag)

# Validations internes
assert permuted_flag == EXPECTED_BUFFER, "Permutation/inversion incohérente"
assert run_full_check(permuted_flag), "La simulation de check() échoue – logique cassée"

# 6. Affichage détaillé
print("KEY (hex)               :", KEY.hex())
print("SECRET (hex)            :", SECRET.hex())
print("Buffer attendu (hex)    :", EXPECTED_BUFFER.hex())
print("Buffer attendu (ASCII)  :", EXPECTED_BUFFER.decode('latin1'))
print("Flag reconstruit        :", user_flag)
print("Longueur flag           :", len(user_flag))
print("Tous les blocs valides ?:", run_full_check(permuted_flag))
print()

# 7. Comparaison avec flag attendu officiel (optionnel)
OFFICIAL = "SHLK{Th3NexT_0nEwoNtBe-s0SimPle}"
print("Flag officiel attendu   :", OFFICIAL)
print("Concordance ?           :", user_flag == OFFICIAL)
if user_flag == OFFICIAL:
    print("\n=> Utilisez ce flag dans le binaire :")
    print(OFFICIAL)
else:
    print("\nATTENTION: Discordance entre reconstruction et flag officiel fourni.")

# 8. Mini self-test : re-simuler permutation + check() sur OFFICIAL
perm_official = apply_permutation(OFFICIAL)
print("\nSelf-test sur OFFICIAL : blocs OK ?",
      run_full_check(perm_official))

# 9. (Debug) différencier si besoin
if user_flag != OFFICIAL:
    print("\nDifférences position par position :")
    for i, (a, b) in enumerate(zip(user_flag, OFFICIAL)):
        if a != b:
            print(f" pos {i:02d}: reconstruit={a!r} attendu={b!r}")
