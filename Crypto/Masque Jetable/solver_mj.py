#!/usr/bin/env python3
"""
Solver pour le challenge "Masque Jetable".

Méthode en quatre étapes :
1) Collecter de nombreux paquets chiffrés (48 octets hex par ligne).
2) Pour chaque position, conserver les k octets les moins fréquents, où
   k est le nombre de positions du flag qui peuvent tomber sur cette
   position (fenêtre de taille 6 car offset ∈ [0,5]).
3) Utiliser les différences de fenêtres glissantes (S[p-1] -> S[p]) :
   l'octet qui sort de la fenêtre donne flag[p-6], celui qui entre donne flag[p].
   On obtient ainsi des ensembles de candidats leave/enter par position.
4) Résoudre par backtracking sous contraintes (unicité des octets, ASCII
   imprimable, fenêtres compatibles avec S) et vérifier les fenêtres suffixes
   (positions 42..47). Le flag reconstruit est unique.
"""

from __future__ import annotations

import argparse
import pickle
import socket
from collections import Counter
from pathlib import Path
from typing import Iterable, List, Sequence, Set


HOST = "challenges.shutlock.fr"
PORT = 50011
PACKET_LEN = 48
FLAG_LEN = 42
OFFSETS = range(PACKET_LEN - FLAG_LEN)  # 0..5
PRINTABLE = set(range(32, 127))


def recv_packets(count: int, host: str, port: int) -> Iterable[bytes]:
    """Envoie `count` retours chariot et renvoie `count` paquets binaires."""
    with socket.create_connection((host, port)) as sock:
        sock.sendall(b"\n" * count)
        remaining = count
        buf = b""
        while remaining and (chunk := sock.recv(65536)):
            buf += chunk
            while b"\n" in buf and remaining:
                line, buf = buf.split(b"\n", 1)
                if not line:
                    continue
                yield bytes.fromhex(line.decode())
                remaining -= 1


def collect_counts(n_packets: int, host: str, port: int) -> List[Counter]:
    """Compte les occurrences de chaque octet par position."""
    counts = [Counter() for _ in range(PACKET_LEN)]
    for pkt in recv_packets(n_packets, host, port):
        if len(pkt) != PACKET_LEN:
            raise ValueError(f"longueur inattendue : {len(pkt)}")
        for pos, byte in enumerate(pkt):
            counts[pos][byte] += 1
    return counts


def k_size(pos: int) -> int:
    """Nombre de positions du flag pouvant se projeter sur `pos`."""
    return len({pos - off for off in OFFSETS if 0 <= pos - off < FLAG_LEN})


def build_sets(counts: Sequence[Counter], margin: int = 0) -> List[Set[int]]:
    """Construit S[p] = ensemble des k+margin octets les moins fréquents à la position p."""
    sets: List[Set[int]] = []
    for pos in range(PACKET_LEN):
        k = k_size(pos)
        low = sorted(counts[pos].items(), key=lambda kv: kv[1])[: k + margin]
        sets.append({b for b, _ in low})
    return sets


def reconstruct_flag(counts: Sequence[Counter], max_margin: int = 20) -> bytes:
    """Tente la reconstruction en élargissant progressivement S[p] si besoin."""
    last_err: RuntimeError | None = None
    for margin in range(max_margin + 1):
        try:
            return _reconstruct_with_margin(counts, margin)
        except RuntimeError as err:
            last_err = err
    raise last_err if last_err else RuntimeError("aucune solution trouvée")


def _reconstruct_with_margin(counts: Sequence[Counter], margin: int) -> bytes:
    S = build_sets(counts, margin=margin)

    leave_opts: List[Set[int] | None] = [None] * FLAG_LEN
    enter_opts: List[Set[int] | None] = [None] * FLAG_LEN

    for p in range(1, PACKET_LEN):
        inter = S[p] & S[p - 1]
        leave = S[p - 1] - inter
        enter = S[p] - inter
        idx = p - 6
        if 0 <= idx < FLAG_LEN:
            leave_opts[idx] = leave
        if p < FLAG_LEN:
            enter_opts[p] = enter

    def allowed_set(pos: int) -> Set[int]:
        sources: List[Set[int]] = []
        if pos < 6:
            sources.append(S[pos])
        if leave_opts[pos] is not None:
            sources.append(set(leave_opts[pos]))  # type: ignore[arg-type]
        if enter_opts[pos] is not None:
            sources.append(set(enter_opts[pos]))  # type: ignore[arg-type]
        if not sources:
            return set()
        inter = set.intersection(*sources)
        inter_print = {b for b in inter if b in PRINTABLE}
        if inter_print:
            base = inter_print
        else:
            base = set().union(*sources)
        printable_only = {b for b in base if b in PRINTABLE}
        return printable_only if printable_only else base

    allowed = [allowed_set(p) for p in range(FLAG_LEN)]
    flag: List[int | None] = [None] * FLAG_LEN
    used: Set[int] = set()
    solutions: List[bytes] = []

    def suffix_ok() -> bool:
        for pos in range(FLAG_LEN, PACKET_LEN):
            window = {b for b in flag[max(0, pos - 5) : FLAG_LEN] if b is not None}
            if not window <= S[pos]:
                return False
        return True

    def dfs(pos: int) -> None:
        if solutions:
            return
        if pos == FLAG_LEN:
            if suffix_ok():
                solutions.append(bytes(flag))  # type: ignore[arg-type]
            return
        opts = allowed[pos]
        for b in opts:
            if b in used:
                continue
            flag[pos] = b
            used.add(b)
            # Petite validation locale : si la fenêtre [pos-5..pos] est complète, elle doit être incluse dans S[pos]
            if pos >= 5 and None not in flag[pos - 5 : pos + 1]:
                window = set(flag[pos - 5 : pos + 1])  # type: ignore[arg-type]
                if not window <= S[pos]:
                    used.remove(b)
                    flag[pos] = None
                    continue
            dfs(pos + 1)
            used.remove(b)
            flag[pos] = None

    dfs(0)
    if not solutions:
        raise RuntimeError(f"aucune solution trouvée (margin={margin})")
    if len(solutions) > 1:
        raise RuntimeError(f"solutions multiples (margin={margin})")
    return solutions[0]


def main() -> None:
    parser = argparse.ArgumentParser(description="Solveur du flag Masque Jetable.")
    parser.add_argument(
        "--packets", type=int, default=200_000, help="nombre de paquets à capturer"
    )
    parser.add_argument(
        "--host", default=HOST, help="hôte du challenge (par défaut challenges.shutlock.fr)"
    )
    parser.add_argument("--port", type=int, default=PORT, help="port du challenge")
    parser.add_argument(
        "--counts",
        type=Path,
        default=Path("counts.pkl"),
        help="fichier pickle pour charger/sauver les comptages",
    )
    args = parser.parse_args()

    if args.counts.exists():
        print(f"[+] Chargement des comptages depuis {args.counts}")
        counts = pickle.loads(args.counts.read_bytes())
    else:
        print(f"[+] Capture de {args.packets} paquets sur {args.host}:{args.port}")
        counts = collect_counts(args.packets, args.host, args.port)
        args.counts.write_bytes(pickle.dumps(counts))
        print(f"[+] Comptages sauvegardés dans {args.counts}")

    print("[+] Reconstruction du flag…")
    flag = reconstruct_flag(counts)
    print(f"[+] Flag : {flag.decode()}")


if __name__ == "__main__":
    main()
