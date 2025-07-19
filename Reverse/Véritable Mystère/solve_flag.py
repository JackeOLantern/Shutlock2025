#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Solveur autonome – challenge « Véritable Mystère »

Usage
-----
    python3 solve_flag.py VeritableMystere.py       -> affiche le flag
    python3 solve_flag.py VeritableMystere.py -r    -> vérifie en lançant le challenge

L’option -r (–run) sert uniquement à montrer le « Mot de passe valide ! » du
script original ; elle est sans incidence sur le calcul du mot de passe.
"""

import re, bz2, base64, sys, importlib.util, builtins, argparse
from typing import List

# --------------------------------------------------------------------------- #
# 1)  Extraction du byte-code brut                                           #
# --------------------------------------------------------------------------- #
def extract_bytecode(chall_path: str) -> bytes:
    src = open(chall_path, encoding="utf-8").read()

    # chaîne base64 → bz2
    b64  = re.search(r"b64decode\('([^']+)'\)", src).group(1)
    inner = bz2.decompress(base64.b64decode(b64))

    # littéral b'…' passé à muNFU(…)
    blob = re.search(rb"muNFU\(\s*b['\"]([^'\"]+)['\"]\s*\)", inner, re.S).group(1)
    return eval(b"b'" + blob + b"'")

# --------------------------------------------------------------------------- #
# 2)  Désassembleur minimal (opcodes utiles)                                 #
# --------------------------------------------------------------------------- #
def disas(bc: bytes) -> List[tuple]:
    pc, out = 0, []
    while pc < len(bc):
        op = bc[pc]; pc += 1
        if op in (194, 145, 216, 30, 126, 97, 201, 53):   # 2 octets d’args
            a, b = bc[pc], bc[pc+1]; pc += 2; out.append((op, a, b))
        elif op in (205, 115, 120, 65, 195, 16):          # 1 octet
            a = bc[pc]; pc += 1;       out.append((op, a))
        else:                                             # opcode 166
            out.append((op,))
    return out

# --------------------------------------------------------------------------- #
# 3)  Reconstruction du mot de passe (32 octets)                              #
# --------------------------------------------------------------------------- #
def solve_password(bc: bytes) -> str:
    ops = disas(bc)

    # 3-a  constantes XOR poussées dans R2 : 53 02 <const>
    xor_consts = [o[2] for o in ops if o[:2] == (53, 2)][:32]

    # 3-b  blocs de bits attendus après chaque POP 115 02
    pops = [i for i, o in enumerate(ops) if o[0] == 115][:32]
    blocks = []
    for i in range(32):
        start, stop = pops[i], pops[i+1] if i+1 < 32 else len(ops)
        bits = [o[2] for o in ops[start:stop] if o[:2] == (194, 5)]
        blocks.append(bits)
    blocks.reverse()                                      # pile LIFO → ordre naturel

    # 3-c  bits (LSB→MSB) → octets clairs
    def bits_to_byte(bits): return sum(b << i for i, b in enumerate(bits))
    plain = [bits_to_byte(b) for b in blocks]

    # 3-d  mot de passe = plain ⊕ xor_const  (même ordre)
    pwd_bytes = bytes(p ^ c for p, c in zip(plain, xor_consts))
    return pwd_bytes.decode()

# --------------------------------------------------------------------------- #
# 4)  (optionnel) : exécute le challenge avec le bon mot de passe            #
# --------------------------------------------------------------------------- #
def run_original(chall_path: str, password: str):
    old_input = builtins.input
    builtins.input = lambda _='': password        # réponse automatique

    spec = importlib.util.spec_from_file_location("vm_mod", chall_path)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)                  # déclenche l’affichage
    builtins.input = old_input

# --------------------------------------------------------------------------- #
# 5)  Point d’entrée                                                          #
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="VeritableMystere.py")
    ap.add_argument("-r", "--run", action="store_true",
                    help="lancer aussi le challenge pour vérifier")
    args = ap.parse_args()

    bytecode = extract_bytecode(args.file)
    flag     = solve_password(bytecode)

    print(f"[+] Mot de passe trouvé : {flag}")

    if args.run:
        print("\n[•] Vérification dans le binaire original :")
        run_original(args.file, flag)
