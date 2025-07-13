#!/usr/bin/env python3
# coding: utf-8

def recover_flag(v: int) -> bytes:
    octets = []
    while v:
        v, rem = divmod(v, 1000)
        octets.append(rem % 256)
    return bytes(octets)

def main():
    with open('out.txt', 'r') as f:
        v_str = f.read().strip().lstrip('(').split(',',1)[0]
    v = int(v_str)

    flag = recover_flag(v)
    try:
        print("FLAG:", flag.decode())
    except UnicodeDecodeError:
        print("FLAG (bytes):", flag)

if __name__ == "__main__":
    main()
