#!/usr/bin/env python3
# check_trace.py : reproduction de encode.wasm/check() avec traces détaillées

B = bytes.fromhex('dc87db6b7cfd6d20')          # octets fixes (offset 8)
A = bytes.fromhex('8bc9da58f2bf1ea1')          # bloc-cible (offset 16)
PWD = b"pureWASM"                              # mot de passe candidat (8 octets)

def rotl32(v, n): n &= 31; return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))
def rotr32(v, n): n &= 31; return (v >> n) | ((v << (32 - n)) & 0xFFFFFFFF)

def check_with_trace(pwd8: bytes) -> bool:
    mem = bytearray(24)
    mem[0:8]  = pwd8
    mem[8:16] = B
    mem[16:24]= A

    print("État initial mem[0..7] :", mem[0:8].hex())
    for i in range(8):
        a = mem[i]
        b = mem[8+i]
        x = a ^ b
        n = x & 31
        dir_right = (x & 1) == 0  # True → ROTR32, False → ROTL32

        # injection de x dans le mot aligné
        w = int.from_bytes(mem[i:i+4], 'little')
        w = (w & 0xFFFFFF00) | x
        mem[i:i+4] = w.to_bytes(4, 'little')

        # trace
        print(f"\n--- Tour i={i} ---")
        print(f" a = {a:#04x}, b = {b:#04x}, x=a^b={x:#04x}")
        print(f" n = {n} (décalage), rotation {'droite' if dir_right else 'gauche'}")

        # rotation sur les deux dwords
        w0 = int.from_bytes(mem[0:4], 'little')
        w1 = int.from_bytes(mem[4:8], 'little')
        if dir_right:
            w0 = rotr32(w0, n)
            w1 = rotr32(w1, n)
        else:
            w0 = rotl32(w0, n)
            w1 = rotl32(w1, n)
        mem[0:4] = w0.to_bytes(4, 'little')
        mem[4:8] = w1.to_bytes(4, 'little')

        print(" mem[0..7] après rot :", mem[0:8].hex())

    print("\nÉtat final mem[0..7]  :", mem[0:8].hex())
    print("Doit être égal à A    :", A.hex())
    return mem[0:8] == A

if __name__ == "__main__":
    ok = check_with_trace(PWD)
    print("\nRésultat check() :", ok)
