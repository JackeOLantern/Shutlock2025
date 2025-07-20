# blocs constants du wasm
B = bytes.fromhex("dc87db6b7cfd6d20")
A = bytes.fromhex("8bc9da58f2bf1ea1")

def rotl32(v,n): n&=31; return ((v<<n)&0xffffffff)|(v>>(32-n))
def rotr32(v,n): n&=31; return (v>>n)|((v<<(32-n))&0xffffffff)

def check(pwd8: bytes) -> bool:
    mem = bytearray(16)
    mem[0:8] = pwd8
    mem[8:16] = B
    for i in range(8):
        a = mem[i]
        b = mem[8+i]
        x = a ^ b
        # remplace l’octet bas d’un dword aligné sur i
        w = int.from_bytes(mem[i:i+4],'little')
        w = (w & 0xffffff00) | x
        mem[i:i+4] = w.to_bytes(4,'little')
        n = x & 31
        if x & 1:   # impair ⇒ ROTL
            mem[0:4] = rotl32(int.from_bytes(mem[0:4],'little'), n).to_bytes(4,'little')
            mem[4:8] = rotl32(int.from_bytes(mem[4:8],'little'), n).to_bytes(4,'little')
        else:       # pair ⇒ ROTR
            mem[0:4] = rotr32(int.from_bytes(mem[0:4],'little'), n).to_bytes(4,'little')
            mem[4:8] = rotr32(int.from_bytes(mem[4:8],'little'), n).to_bytes(4,'little')
    return mem[0:8] == A

print( check(b"pureWASM") )   # → True
