#!/usr/bin/env python3
import argparse, hashlib, json, os, re, sys, binascii, itertools
from pathlib import Path

try:
    from Crypto.Cipher import AES                   # PyCryptodome
except ImportError:
    sys.exit("Installez PyCryptodome : "
             "python -m pip install --break-system-packages pycryptodome")

# ────────────────────────── extraction de chaînes ──────────────────────────
ASCII  = re.compile(rb"[ -~]{4,64}")                # 4 à 64 car.
UTF16  = re.compile(rb"(?:[ -~]\x00){4,64}")

def strings(buf: bytes):
    yield from (m.group(0) for m in ASCII.finditer(buf))
    yield from (m.group(0).replace(b"\x00", b"") for m in UTF16.finditer(buf))

def raw_rodata(binfile: Path):
    data = binfile.read_bytes()
    off  = data.find(b".rodata")                    # heuristique simple
    return data[off:] if off != -1 else b""

# ────────────────────────── dérivation clé / IV ────────────────────────────
def key_iv_pairs(seed: bytes):
    key = hashlib.sha256(seed).digest()[:16]
    yield key, hashlib.sha256(seed[::-1]).digest()[:16]   # dérivation classique
    yield key, key                                        # IV = key
    yield key, b"\0"*16                                   # IV nul

def unpad(buf: bytes):
    if not buf: return buf
    last = buf[-1]
    if 1 <= last <= 0x10 and buf.endswith(bytes([last])*last):
        return buf[:-last]
    return buf.rstrip(b"\x00")

def decrypt(blob: bytes, key: bytes, iv: bytes):
    if len(blob) % 16:
        return None
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(blob)
    plain = unpad(plain)
    for mode in ("strict", "ignore"):                     # UTF-8 strict puis tolérant
        try:
            return json.loads(plain.decode("utf-8", errors=mode))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return None

# ────────────────────────── recherche des fichiers ─────────────────────────
def locate(root: Path):
    malware = cfg = None
    for p in root.rglob("*"):
        if not p.is_file(): continue
        if p.name == "config.bin":
            cfg = p
        elif p.name == "._" or os.access(p, os.X_OK):
            malware = p
        if malware and cfg:
            break
    if not (malware and cfg):
        sys.exit("Binaire ou config.bin introuvables.")
    return malware, cfg

# ────────────────────────── bruteforce intelligent ─────────────────────────
def brute(malware: Path, cfg: Path):
    blob = cfg.read_bytes()
    tested = set()

    # 0) graine connue (e-mail + NUL)
    KNOWN = b"star_wars_official@proton.me\x00"
    for k, iv in key_iv_pairs(KNOWN):
        js = decrypt(blob, k, iv)
        if js:
            return KNOWN, k, iv, js

    # 1) chaînes ASCII / UTF-16 dans le binaire + .rodata
    sources = itertools.chain(strings(malware.read_bytes()),
                              strings(raw_rodata(malware)))
    for raw in sources:
        for seed in (raw, raw + b"\0", raw + b"\0\0"):
            if seed in tested:
                continue
            tested.add(seed)
            for k, iv in key_iv_pairs(seed):
                js = decrypt(blob, k, iv)
                if js:
                    return seed, k, iv, js
    return None

# ────────────────────────── programme principal ────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Déchiffre automatiquement tmp/config.bin et affiche le flag.")
    ap.add_argument("root", nargs="?", default=".",
                    help="Dossier racine du dump (défaut : .)")
    ap.add_argument("--malware", help="Chemin explicite du binaire")
    ap.add_argument("--cfg",     help="Chemin explicite de config.bin")
    args = ap.parse_args()
    root = Path(args.root).resolve()

    if args.malware and args.cfg:
        malware = Path(args.malware).resolve()
        cfg     = Path(args.cfg).resolve()
    else:
        malware, cfg = locate(root)

    print(f"[+] Binaire : {malware}")
    print(f"[+] Config  : {cfg}")

    res = brute(malware, cfg)
    if not res:
        sys.exit("[-] Échec : graine obfusquée ou non trouvée.")
    seed, key, iv, js = res

    sha  = hashlib.sha256(malware.read_bytes()).hexdigest()
    flag = f"SHLK{{{sha}:{seed.decode(errors='ignore')}:{cfg}}}"

    print("\n[✓] JSON déchiffré :")
    print(json.dumps(js, indent=2))
    print("\n[✓] Graine :", seed.decode('latin1', 'ignore'))
    print("[✓] KEY   :", binascii.hexlify(key).decode())
    print("[✓] IV    :", binascii.hexlify(iv).decode())
    print("\n[★] FLAG  :", flag)

if __name__ == "__main__":
    main()
