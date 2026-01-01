#!/usr/bin/env python3
"""
masque_solver.py - Shutlock 2025 « Masque Jetable » solver (final)
===================================================================
USAGE:
  python3 masque_solver.py --LOCAL               # mode local
  python3 masque_solver.py --DISTANT             # mode distant
  python3 masque_solver.py --DISTANT --tail      # mode distant, écoute infinie
  python3 masque_solver.py --VISUAL              # génère heatmap

Options:
  --count N       nombre de paquets (défaut: 200) ignoré si --tail
  --tail          écoute sans limite jusqu'à détection du flag
  --workers N     connexions parallèles (mode distant)
  --flag-only     n'affiche que le flag
  --out FILE      fichier de sortie (défaut: flag.txt)

Description:
  • LOCAL: extrait directement la constante FLAG du binaire Rust.
  • DISTANT: lit paquets via socket, détecte un flag en clair (!contrainte SHLK{...}).
  • VISUAL: produit une heatmap des octets stables dans : packets_dump.txt.
"""
from __future__ import annotations
import argparse, subprocess, socket, re, sys, string
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from collections import Counter
import numpy as np
import matplotlib.pyplot as plt

# ------------------ MODE LOCAL ------------------
def spawn_local(count: int) -> list[str]:
    bin_path = Path("./target/release/masque_jetable")
    if not bin_path.exists():
        sys.exit("❌ Binaire introuvable: compile avec 'cargo build --release'.")
    proc = subprocess.Popen(
        [str(bin_path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, bufsize=1, text=True)
    assert proc.stdin and proc.stdout
    packets: list[str] = []
    for _ in tqdm(range(count), desc="LOCAL", unit="pkt"):
        proc.stdin.write("\n")
        proc.stdin.flush()
        line = proc.stdout.readline().strip()
        packets.append(line)
    proc.kill()
    return packets

# ------------------ MODE DISTANT ------------------
def read_remote(count: int, tail: bool=False,
                host: str="challenges.shutlock.fr", port: int=50011,
                workers: int=1) -> list[str]:
    packets: list[str] = []
    def worker(n_pkts: int):
        sock = socket.create_connection((host, port))
        f = sock.makefile('r')
        out = []
        try:
            if tail:
                while True:
                    sock.sendall(b"\n")
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    out.append(line)
            else:
                for _ in range(n_pkts):
                    sock.sendall(b"\n")
                    line = f.readline()
                    if not line:
                        break
                    line = line.strip()
                    out.append(line)
        finally:
            sock.close()
        return out

    jobs = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        per_worker = count // workers if not tail else count
        for _ in range(workers):
            jobs.append(executor.submit(worker, per_worker))
        for future in tqdm(as_completed(jobs), total=workers, desc="DISTANT", unit="thr"):
            res = future.result()
            packets.extend(res)
    return packets

# ------------------ RECONSTRUCTION LOCAL DIRECTE ------------------
def reconstruct_local() -> str | None:
    bin_path = Path("./target/release/masque_jetable")
    if not bin_path.exists():
        return None
    data = bin_path.read_bytes()
    m = re.search(rb"CTF/([0-9A-Fa-f]{32})/", data)
    if m:
        return f"SHLK{{{m.group(1).decode()}}}"
    return None

# ------------------ HEATMAP ------------------
def make_heatmap(lines: list[str], out_png: str="heatmap.png"):
    data = [bytes.fromhex(l) for l in lines if len(l) == 96]
    if not data:
        sys.exit("❌ Aucun paquet hex valide pour heatmap.")
    mat = np.zeros((256, 48), dtype=int)
    for bl in data:
        for i, b in enumerate(bl):
            mat[b, i] += 1
    mat = mat / len(data)
    plt.figure(figsize=(12, 6))
    plt.imshow(mat, aspect='auto', cmap='viridis')
    plt.colorbar(label='Fréquence')
    plt.title('Stabilité des octets par position')
    plt.xlabel('Position'); plt.ylabel('Octet')
    plt.tight_layout(); plt.savefig(out_png)
    print(f"🖼️ Heatmap enregistrée dans {out_png}")

# ------------------ FLAG DETECTION HEURISTIC ------------------
def likely_flag(s: str) -> bool:
    return len(s) >= 16 and all(c in string.printable for c in s) and any(c.isalnum() for c in s)

# ------------------ MAIN ------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--LOCAL', action='store_true', help='Mode local')
    ap.add_argument('--DISTANT', action='store_true', help='Mode distant')
    ap.add_argument('--count', type=int, default=200, help='Nombre de paquets')
    ap.add_argument('--tail', action='store_true', help='Lecture infinie')
    ap.add_argument('--workers', type=int, default=4, help='Connexions parallèles')
    ap.add_argument('--flag-only', action='store_true', help='Affiche seulement le flag')
    ap.add_argument('--out', type=str, default='flag.txt', help='Fichier de sortie')
    ap.add_argument('--VISUAL', action='store_true', help='Génère heatmap')
    args = ap.parse_args()

    if args.VISUAL:
        lines = Path('packets_dump.txt').read_text().splitlines()
        make_heatmap(lines)
        return
    if not (args.LOCAL ^ args.DISTANT):
        ap.error('Spécifie exactement un mode --LOCAL ou --DISTANT')

    if args.LOCAL:
        packets = spawn_local(args.count)
    else:
        packets = read_remote(args.count, tail=args.tail, workers=args.workers)

    Path('packets_dump.txt').write_text("\n".join(packets))

    # récupération du flag
    flag: str | None = None
    if args.LOCAL:
        flag = reconstruct_local()
    else:
        for line in packets:
            if likely_flag(line):
                flag = line
                break

    # sortie
    if flag:
        Path(args.out).write_text(flag + '\n')
        if args.flag_only:
            print(flag)
        else:
            print(f"\n✅ FLAG → {flag}")
            # essai de décodage ASCII si possible
            try:
                if all(c in "0123456789abcdef" for c in flag.lower()) and len(flag) % 2 == 0:
                    ascii_flag = bytes.fromhex(flag).decode('ascii', errors='replace')
                    print(f"🔍 Interprétation ASCII: {ascii_flag}")
            except Exception:
                pass
            print(f"Sauvegardé dans {args.out}")
    else:
        print('❌ Flag non trouvé - augmente --count ou vérifie le flux.')

if __name__ == '__main__':
    main()
