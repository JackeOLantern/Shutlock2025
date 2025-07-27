#!/usr/bin/env python3
"""
auto_decrypt_config.py
──────────────────────
Déchiffre automatiquement tmp/config.bin et affiche le JSON clair (flag inclus).

• recherche récursive du binaire malware (tmp/._ ou tout exécutable caché) et de config.bin
• extraction de toutes les chaînes ASCII / UTF-16 du binaire
• dérivation clé / IV par SHA-256(seed) + trois variantes IV
• test successif de chaque couple → dès qu’un JSON valide apparaît, on l’affiche
"""

import argparse, hashlib, json, os, re, sys, binascii
from pathlib import Path

try:
    from Crypto.Cipher import AES          # PyCryptodome
except ImportError as e:
    sys.exit("PyCryptodome manquant : python -m pip install --break-system-packages pycryptodome")

# ---------------------------------------------------------------------
# 1) outils "strings" : ASCII 6-64, UTF-16LE 6-64
ASCII  = re.compile(rb"[ -~]{6,64}")
UTF16  = re.compile(rb"(?:[ -~]\x00){6,64}")

def iter_strings(data: bytes):
    for m in ASCII.finditer(data):
        yield m.group(0)
    for m in UTF16.finditer(data):
        yield m.group(0).replace(b"\x00", b"")

# ---------------------------------------------------------------------
# 2) génération clé / IV à partir d’un seed
def key_iv_pairs(seed: bytes):
    key = hashlib.sha256(seed).digest()[:16]
    yield key, hashlib.sha256(seed[::-1]).digest()[:16]  # schéma courant
    yield key, key                                       # IV = key
    yield key, b"\x00" * 16                              # IV nul

# ---------------------------------------------------------------------
# 3) tentative de déchiffrement + validation JSON
def try_decrypt(blob: bytes, key: bytes, iv: bytes):
    if len(blob) % 16:
        return None
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(blob).rstrip(b"\x00")
    for mode in ("strict", "ignore"):        # strict → UTF-8 pur, ignore → best-effort
        try:
            return json.loads(plain.decode("utf-8", errors=mode))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return None

# ---------------------------------------------------------------------
# 4) localisation (ou arguments explicites)
def locate_files(root: Path):
    malware = cfg = None
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name == "config.bin":
            cfg = p
            continue
        if p.name == "._" or os.access(p, os.X_OK):
            malware = p
        if malware and cfg:
            break
    if not (malware and cfg):
        sys.exit("Impossible de trouver le binaire ou config.bin")
    return malware, cfg

# ---------------------------------------------------------------------
def brute(malware: Path, cfg: Path):
    blob_cfg = cfg.read_bytes()
    tested   = set()
    for raw in iter_strings(malware.read_bytes()):
        for seed in (raw, raw + b"\x00"):         # test version NUL-terminée
            if seed in tested:
                continue
            tested.add(seed)
            for key, iv in key_iv_pairs(seed):
                js = try_decrypt(blob_cfg, key, iv)
                if js is not None:
                    return seed, key, iv, js
    return None, None, None, None

# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Déchiffre tmp/config.bin et affiche le flag")
    ap.add_argument("root", nargs="?", default=".", help="Dossier racine du dump (défaut : .)")
    ap.add_argument("--malware", help="Chemin explicite du binaire (optionnel)")
    ap.add_argument("--cfg",     help="Chemin explicite de config.bin (optionnel)")
    args = ap.parse_args()

    root = Path(args.root).resolve()

    if args.malware and args.cfg:
        malware = Path(args.malware).resolve()
        cfg     = Path(args.cfg).resolve()
    else:
        malware, cfg = locate_files(root)

    print(f"[+] Binaire : {malware}")
    print(f"[+] Config  : {cfg}")

    seed, key, iv, js = brute(malware, cfg)
    if js is None:
        sys.exit("[-] Échec : aucune combinaison n’a donné un JSON valide")

    sha = hashlib.sha256(malware.read_bytes()).hexdigest()
    flag = f"SHLK{{{sha}:{seed.decode(errors='ignore')}:{cfg}}}"

    print("\n[✓] JSON déchiffré :")
    print(json.dumps(js, indent=2))
    print("\n[✓] Graine :", seed.decode('latin1', 'ignore'))
    print("[✓] KEY   :", binascii.hexlify(key).decode())
    print("[✓] IV    :", binascii.hexlify(iv).decode())
    print("\n[★] FLAG  :", flag)

# ---------------------------------------------------------------------
if __name__ == "__main__":
    main()
