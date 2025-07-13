#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def extract_base1000(n: int):
    """Décompose n en restes base 1000, affiche chaque rem_i et caractère possible."""
    rems = []
    i = 0
    print("🔍 Début de la décomposition base 1000\n")
    while n:
        old_n = n
        n, rem = divmod(n, 1000)
        ch = chr(rem) if 32 <= rem < 127 else '?'
        print(f"Step {i:02d}: divmod({old_n}, 1000) → quotient = {n}, rem_i = {rem} → '{ch}'")
        rems.append(rem)
        i += 1
    print("\n✅ Fin de la décomposition : rems =", rems, "\n")
    return rems

def recover_flag(rem_list):
    """Convertit chaque rem_i en caractère ASCII imprimable et reconstitue le flag."""
    chars = []
    print("🔨 Reconstruction du flag à partir de tous les rem_i\n")
    for i, rem in enumerate(rem_list):
        if not 32 <= rem < 127:
            raise ValueError(f"⛔ Erreur : code {rem} (indice {i}) n’est pas un ASCII imprimable")
        print(f" rem[{i:02d}] = {rem} → caractère '{chr(rem)}'")
        chars.append(chr(rem))
    flag = ''.join(chars)
    print("\n✅ Flag reconstitué :", flag)
    return flag

def main():
    # 1️⃣ Lecture de v et first
    with open('out.txt', 'r') as f:
        s = f.read().strip().strip('()')
    v_str, first_str = s.split(',', 1)
    v, first = int(v_str), int(first_str)
    print("🏁 Lecture initale")
    print(" v (nuage de données)     =", v)
    print(" first (constante LTE)    =", first)

    # 2️⃣ Soustraction de la constante
    M = v - first
    print(f"\n2️⃣ M = v − first = {M}\n")

    # 3️⃣ Décomposition base 1000 (extraction des rem_i)
    rems = extract_base1000(M)

    # 4️⃣ Reconstruction ASCII et flag
    flag = recover_flag(rems)
    print(f"\n🎯 FLAG final = {flag}")

if __name__ == "__main__":
    main()
