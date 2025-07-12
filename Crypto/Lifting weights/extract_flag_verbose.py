# extract_flag_verbose.py

# ⚠️ Remplace cette ligne par le contenu exact de out.txt
with open('out.txt') as fd:
    encrypted = eval(fd.read().strip())

flag_bytes = []

for i, (r, f) in enumerate(encrypted):
    print(f"--- Octet #{i} ---")
    print(f"r = {r}")
    print(f"f = {f}")

    denom = 2 * r
    print(f"Calcul de l'octet b = f // (2*r) avec 2*r = {denom}")

    if f % denom != 0:
        raise ValueError(f"[ERREUR] Tuple {i} : f={f} n’est pas divisible par 2*r={denom}")
    else:
        print(f"[OK] f est divisible par 2*r")

    b = f // denom
    print(f"Résultat b = {b} (valeur entière)")

    if not (0 <= b < 256):
        raise ValueError(f"[ERREUR] Tuple {i} : octet invalide b={b}")
    else:
        print(f"[OK] octet b est dans la plage valide [0;255]")

    flag_bytes.append(b)
    print(f"Octet ASCII correspondant: {b} -> '{chr(b)}'\n")

flag = bytes(flag_bytes)
print("=== Flag complet ===")
print(flag)
