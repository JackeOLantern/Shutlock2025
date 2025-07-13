#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def extract_base1000(n: int):
    """Décompose n en restes base 1000, et affiche chaque rem_i"""
    rems = []
    i = 0
    while n:
        n, rem = divmod(n, 1000)
        print(f"[i={i:02d}] rem_i = {rem} → {chr(rem) if 32 <= rem < 127 else '?'}")
        rems.append(rem)
        i += 1
    return rems

def recover_flag(rem_list):
    """Convertit chaque rem_i en caractère, reconstitue et renvoie le flag"""
    chars = []
    for i, rem in enumerate(rem_list):
        if not 32 <= rem < 127:
            raise ValueError(f"Le code {rem} (à l’indice {i}) n’est pas un ASCII imprimable")
        chars.append(chr(rem))
    return ''.join(chars)

def main():
    # Lecture de v et first
    with open('out.txt', 'r') as f:
        s = f.read().strip().strip('()')
    v_str, first_str = s.split(',', 1)
    v, first = int(v_str), int(first_str)
    print("Lue : v =", v)
    print("       first =", first)

    # On retire la constante fixe
    M = v - first
    print("\nM = v – first =", M, "\n")

    # Extraction des codes ASCII
    rems = extract_base1000(M)

    # Reconstruction du flag
    flag = recover_flag(rems)
    print("\n🎯 FLAG :", flag)

if __name__ == "__main__":
    main()
