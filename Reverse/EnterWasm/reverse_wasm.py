#!/usr/bin/env python3
# -*- coding: utf-8 -*-

MAGIC = b'\x00asm'
DATA_SEC_ID = 11

def read_u32_leb(buf, off):
    res = 0; shift = 0; p = off
    while True:
        b = buf[p]; p += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, p

def iter_sections(blob):
    p = 8
    while p < len(blob):
        sid = blob[p]; p += 1
        size, np = read_u32_leb(blob, p)
        payload = blob[np:np+size]
        yield sid, payload
        p = np + size

def extract_segments(blob):
    segs = []
    for sid, payload in iter_sections(blob):
        if sid == DATA_SEC_ID:
            q = 0
            count, q = read_u32_leb(payload, q)
            for _ in range(count):
                mode = payload[q]; q += 1
                if mode != 0:
                    raise ValueError("Segment passif/non géré.")
                assert payload[q] == 0x41; q += 1
                off, q = read_u32_leb(payload, q)
                assert payload[q] == 0x0B; q += 1
                size, q = read_u32_leb(payload, q)
                data = payload[q:q+size]; q += size
                if len(data) == 8:
                    segs.append((off, data))
    return sorted(segs, key=lambda x: x[0])

def rotl32(v,n): n &= 31; return ((v<<n)&0xffffffff)|(v>>(32-n))
def rotr32(v,n): n &= 31; return (v>>n)|((v<<(32-n))&0xffffffff)

def forward_check(pwd, B, A):
    mem = bytearray(16)
    mem[0:8] = pwd
    mem[8:16] = B
    for i in range(8):
        x = mem[i] ^ mem[8+i]
        mem[i] = x
        n = x & 31
        w0 = int.from_bytes(mem[0:4],'little')
        w1 = int.from_bytes(mem[4:8],'little')
        if (x & 1) == 0:
            w0 = rotr32(w0, n); w1 = rotr32(w1, n)
        else:
            w0 = rotl32(w0, n); w1 = rotl32(w1, n)
        mem[0:4] = w0.to_bytes(4,'little')
        mem[4:8] = w1.to_bytes(4,'little')
    return mem[0:8] == A

def reverse_pwd(B, A):
    state_after = bytearray(A)
    pwd = [0]*8
    for i in reversed(range(8)):
        found = False
        for x in range(256):
            n = x & 31
            rotr_forward = (x & 1) == 0
            w0 = int.from_bytes(state_after[0:4],'little')
            w1 = int.from_bytes(state_after[4:8],'little')
            if rotr_forward:
                w0i = rotl32(w0,n); w1i = rotl32(w1,n)
            else:
                w0i = rotr32(w0,n); w1i = rotr32(w1,n)
            pre_rot = bytearray(8)
            pre_rot[0:4] = w0i.to_bytes(4,'little')
            pre_rot[4:8] = w1i.to_bytes(4,'little')
            if pre_rot[i] != x:
                continue
            a = x ^ B[i]
            before = bytearray(pre_rot)
            before[i] = a
            # Validation locale
            test = bytearray(before)
            x2 = test[i] ^ B[i]
            test[i] = x2
            nn = x2 & 31
            tw0 = int.from_bytes(test[0:4],'little')
            tw1 = int.from_bytes(test[4:8],'little')
            if (x2 & 1) == 0:
                tw0 = rotr32(tw0, nn); tw1 = rotr32(tw1, nn)
            else:
                tw0 = rotl32(tw0, nn); tw1 = rotl32(tw1, nn)
            test[0:4] = tw0.to_bytes(4,'little')
            test[4:8] = tw1.to_bytes(4,'little')
            if test != state_after:
                continue
            state_after = before
            pwd[i] = a
            found = True
            break
        if not found:
            raise RuntimeError(f"Echec inversion à i={i}")
    # return bytes(pwd)
    # À ce stade, state_after contient l’état avant l’itération i=0,
    # donc exactement les 8 octets du mot de passe original.
    return bytes(state_after)


def main():
    blob = open("encode.wasm","rb").read()
    if blob[:4] != MAGIC:
        print("Pas un WASM valide"); return
    segs = extract_segments(blob)
    eight = [s for s in segs if len(s[1])==8]
    if len(eight) < 2:
        print("Segments insuffisants"); return
    B = eight[0][1]; A = eight[1][1]
    pwd = reverse_pwd(B,A)
    print("Mot de passe:", pwd.decode('latin1'), pwd.hex())
    print("Forward OK ?", forward_check(pwd,B,A))
    print(f"Flag: SHLK{{{pwd.decode('latin1')}}}")

if __name__ == "__main__":
    main()
