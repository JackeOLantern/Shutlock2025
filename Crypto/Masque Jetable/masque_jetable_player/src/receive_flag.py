#!/usr/bin/env python3
import argparse, subprocess, sys, socket, re
from tqdm import tqdm

# Regex pour détecter le flag final
FLAG_RE = re.compile(r"SHLK\{[a-zA-Z0-9_\-']+\}")

def consume_lines(iterable, total=None, desc="Paquets"):
    pbar = tqdm(iterable, total=total, desc=desc, unit="pkt")
    for raw in pbar:
        line = raw.strip()
        if not line:
            continue
        print(line)
        m = FLAG_RE.search(line)
        if m:
            print(f"\n✅ Flag trouvé : {m.group(0)}")
            sys.exit(0)
    print(f"\n❌ Aucun flag détecté après {total or '∞'} paquets.")
    sys.exit(1)

def remote_mode(host, port, count=None):
    """Connexion socket en REMOTE (netcat)."""
    sock = socket.create_connection((host, port))
    f = sock.makefile('r')
    migrate = (line for line in f)
    consume_lines(migrate, total=count, desc="REMOTE")
    sock.close()

def local_mode(cmd, count=None):
    """Exécution d’un binaire local."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert p.stdout
    consume_lines(p.stdout, total=count, desc="LOCAL")
    p.kill()

def main():
    parser = argparse.ArgumentParser(description="Récupérer le flag via masque jetable")
    parser.add_argument("--mode", choices=["remote","local"], required=True)
    parser.add_argument("--host", default="challenges.shutlock.fr")
    parser.add_argument("--port", type=int, default=50011)
    parser.add_argument("--cmd", nargs=argparse.REMAINDER,
                        help="Commande locale à exécuter (ex: ./masque_jetable)")
    parser.add_argument("--count", type=int, default=None,
                        help="Nombre maximum de paquets à lire")
    args = parser.parse_args()

    if args.mode == "remote":
        remote_mode(args.host, args.port, args.count)
    else:
        if not args.cmd:
            print("🛑 En mode local, précisez --cmd ./masque_jetable", file=sys.stderr)
            sys.exit(1)
        local_mode(args.cmd, args.count)

if __name__ == "__main__":
    main()
