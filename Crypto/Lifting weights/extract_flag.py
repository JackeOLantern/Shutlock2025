# lecture depuis out.txt :
with open('out.txt') as fd:
    encrypted = eval(fd.read().strip())

flag_bytes = []
for i, (r, f) in enumerate(encrypted):
    if f % (2 * r) != 0:
        raise ValueError(f"Tuple {i} : f={f} non multiple de 2*r={2*r}")
    b = f // (2 * r)
    if not (0 <= b < 256):
        raise ValueError(f"Tuple {i} : octet invalide b={b}")
    flag_bytes.append(b)

flag = bytes(flag_bytes)
print(flag)
