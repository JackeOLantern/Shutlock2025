#!/usr/bin/env python3
"""
Solver for the “Secrets Pas Partagés” challenge.

It recovers the shared Diffie-Hellman secret on the custom Edwards curve
described in DOCUMENTATION.md, derives the AES session key, and decrypts
the captured ciphertext to reveal the ASCII secret.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from hashlib import sha256
from pathlib import Path

from Crypto.Cipher import AES

# --- Challenge constants (from DOCUMENTATION.md) -----------------------------
p = 0xFF536875746C6F636B43544632303235BACE001E54B565992D1483B7A59B8363
c = 0x1158561388CE824CD3957318336CABA40E973A9B56C7CB1C23013D8827874A2B
d = 0xFA3030406DEC4E66AE15C74D1E91C7389BF6A4D6FC92846EF32EB204914E81B7
Gx = 0xD70AD808D9C50BB55F57DF9055D8E78795CB5272AD18BF759863A37C44481786
Gy = 0x9443B4D11853F243930A9A979B867CA1C573EC32BE970CA578DCF267D0BE55C0

# Edwards model after normalisation by c: x^2 + y^2 = 1 + d' x^2 y^2
dp = (pow(c, 4, p) * d) % p
inv_c = pow(c, -1, p)

# Full factorisation of ord(G) (pre-computed with Sage / sympy)
ORDER_FACTORS = [
    (2, 2),
    (5, 1),
    (55_763, 1),
    (52_579, 1),
    (183_678_983, 1),
    (7_094_429_431_169, 1),
    (101_837, 1),
    (1_663_966_639, 1),
    (33_086_773, 1),
    (17_107_097_727_061, 1),
    (7_878_749_717, 1),
]
ORDER = 1
for _q, _e in ORDER_FACTORS:
    ORDER *= _q ** _e

ID = (0, 1, 1, 0)  # neutral element in extended coordinates
CHUNK = 50_000    # batch size for BSGS (memory/speed trade-off)
VERBOSE = False

KNOWN_CLIENT_SCALAR = 38697047932418357745524825265068042169507070702890398736572336839066418989611


def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)


# --- Finite-field / Edwards helpers -----------------------------------------
def add(P, Q):
    """Extended twisted-Edwards addition, a=1."""
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = (X1 * X2) % p
    B = (Y1 * Y2) % p
    Cc = (dp * T1 * T2) % p
    D = (Z1 * Z2) % p
    E = ((X1 + Y1) * (X2 + Y2) - A - B) % p
    F = (D - Cc) % p
    Gv = (D + Cc) % p
    H = (B - A) % p
    return (E * F) % p, (Gv * H) % p, (F * Gv) % p, (E * H) % p


def double(P):
    """Point doubling in extended coordinates."""
    X1, Y1, Z1, _ = P
    A = (X1 * X1) % p
    B = (Y1 * Y1) % p
    Cc = (2 * Z1 * Z1) % p
    E = (X1 + Y1) % p
    E = (E * E - A - B) % p
    Gv = (A + B) % p
    F = (Gv - Cc) % p
    H = (A - B) % p
    return (E * F) % p, (Gv * H) % p, (F * Gv) % p, (E * H) % p


def neg(P):
    X, Y, Z, T = P
    return (-X) % p, Y, Z, (-T) % p


def scalar_mul(P, n):
    R = ID
    Q = P
    while n:
        if n & 1:
            R = add(R, Q)
        Q = double(Q)
        n //= 2
    return R


def to_affine(P):
    X, Y, Z, _ = P
    invZ = pow(Z, p - 2, p)
    return (X * invZ) % p, (Y * invZ) % p


def batch_inv(vals):
    """Batch inversion: returns list of 1/vals[i] mod p."""
    n = len(vals)
    prefix = [1] * n
    prod = 1
    for i, v in enumerate(vals):
        prod = (prod * v) % p
        prefix[i] = prod
    inv_prod = pow(prod, p - 2, p)
    out = [0] * n
    for i in reversed(range(n)):
        prev = prefix[i - 1] if i > 0 else 1
        out[i] = (inv_prod * prev) % p
        inv_prod = (inv_prod * vals[i]) % p
    return out


# --- Discrete log machinery --------------------------------------------------
def crt(a1, m1, a2, m2):
    """Chinese Remainder for coprime moduli."""
    inv = pow(m1, -1, m2)
    x = (a2 - a1) * inv % m2
    return (a1 + x * m1) % (m1 * m2), m1 * m2


def bsgs(g, h, order, chunk=CHUNK):
    """
    Baby-step/giant-step with batched inversions.
    Returns x such that x*g = h in subgroup of given order.
    """
    m = int(math.isqrt(order)) + 1
    table = {}

    # Baby steps
    P = ID
    j = 0
    while j < m:
        steps = min(chunk, m - j)
        batch = []
        for _ in range(steps):
            batch.append(P)
            P = add(P, g)
        invz = batch_inv([pt[2] for pt in batch])
        for idx, (pt, iz) in enumerate(zip(batch, invz)):
            table[(pt[0] * iz) % p, (pt[1] * iz) % p] = j + idx
        j += steps

    # Giant steps
    mG = scalar_mul(g, m)
    step_vec = neg(mG)
    i = 0
    R = h
    while i <= m:
        if VERBOSE and i and m > 0 and i % max(1, m // 10) == 0:
            vprint(f"    [bsgs] processed {i}/{m} giant steps")
        steps = min(chunk, m + 1 - i)
        batch = []
        cur = R
        for _ in range(steps):
            batch.append(cur)
            cur = add(cur, step_vec)
        invz = batch_inv([pt[2] for pt in batch])
        for k, (pt, iz) in enumerate(zip(batch, invz)):
            key = ((pt[0] * iz) % p, (pt[1] * iz) % p)
            j_val = table.get(key)
            if j_val is not None:
                return (i + k) * m + j_val
        i += steps
        R = cur

    raise ValueError("discrete log not found")


def pohlig_hellman(G, H, chunk=CHUNK):
    """Solve x such that x*G = H using the known factorisation of ord(G)."""
    order = ORDER

    x = 0
    mod = 1
    for q, e in ORDER_FACTORS:
        sub_order = q ** e
        cofactor = order // sub_order
        g_sub = scalar_mul(G, cofactor)
        h_sub = scalar_mul(H, cofactor)

        # Sanity: both should live in the subgroup
        if to_affine(scalar_mul(g_sub, sub_order)) != (0, 1):
            raise ValueError("generator projection not in expected subgroup")
        if to_affine(scalar_mul(h_sub, sub_order)) != (0, 1):
            raise ValueError("target projection not in expected subgroup")

        vprint(f"[*] dlog in subgroup {q}^{e} (order {sub_order})")
        if sub_order <= 1_000_000:
            acc = ID
            comp = None
            for k in range(sub_order):
                if to_affine(acc) == to_affine(h_sub):
                    comp = k
                    break
                acc = add(acc, g_sub)
            if comp is None:
                raise ValueError(f"dlog failed in tiny subgroup {sub_order}")
        else:
            comp = bsgs(g_sub, h_sub, sub_order, chunk=chunk)

        x, mod = crt(x, mod, comp, sub_order)
        print(f"[+] dlog mod {q}^{e}: {comp}")

    return x % order


# --- Glue code --------------------------------------------------------------
def load_pqivc(path: Path) -> tuple:
    data = json.loads(Path(path).read_text())
    PX = int(data["PX"], 16)
    PY = int(data["PY"], 16)
    QX = int(data["QX"], 16)
    QY = int(data["QY"], 16)
    iv = bytes.fromhex(data["IV"])
    ct = bytes.fromhex(data["CIPH"])
    return PX, PY, QX, QY, iv, ct


def main():
    parser = argparse.ArgumentParser(description="Solver for Secrets Pas Partagés (DHutlock)")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose progress (PH/BSGS and steps)")
    parser.add_argument("--pqivc", type=Path, default=Path("pqivc.json"), help="path to pqivc.json (default: %(default)s)")
    parser.add_argument(
        "--scalar",
        type=int,
        help="known private scalar to skip discrete log (acts on --scalar-on point)",
    )
    parser.add_argument(
        "--scalar-on",
        choices=["P", "Q"],
        default="P",
        help="point to multiply when --scalar is provided (P = server secret b, Q = client secret a)",
    )
    parser.add_argument(
        "--chunk",
        type=int,
        default=CHUNK,
        help="BSGS batch size (memory/speed trade-off, default: %(default)s)",
    )
    parser.add_argument(
        "--force-dlog",
        action="store_true",
        help="force a full PH+BSGS discrete log even if a known scalar is available",
    )
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose

    PX, PY, QX, QY, iv, ct = load_pqivc(args.pqivc)

    # Normalise points (divide by c) to work on a=1 curve
    P = (PX * inv_c) % p, (PY * inv_c) % p, 1, (PX * inv_c % p) * (PY * inv_c % p) % p
    Q = (QX * inv_c) % p, (QY * inv_c) % p, 1, (QX * inv_c % p) * (QY * inv_c % p) % p
    G = (Gx * inv_c) % p, (Gy * inv_c) % p, 1, (Gx * inv_c % p) * (Gy * inv_c % p) % p

    secret_point = None
    b = None
    if args.scalar is not None:
        vprint(f"[*] Skipping discrete log, using provided scalar on {args.scalar_on}")
        if args.scalar_on == "P":
            b = args.scalar % ORDER
            secret_point = scalar_mul(P, b)
            print(f"[✓] Using provided b (server scalar): {b}")
        else:
            a = args.scalar % ORDER
            secret_point = scalar_mul(Q, a)
            print(f"[✓] Using provided a (client scalar): {a}")
    elif not args.force_dlog:
        # Fast path: reuse known client scalar a from the documentation example
        a = KNOWN_CLIENT_SCALAR % ORDER
        secret_point = scalar_mul(Q, a)
        print(f"[✓] Using known client scalar a (doc example): {a}")
    else:
        print("[*] Solving discrete log Q = b·G …")
        b = pohlig_hellman(G, Q, chunk=args.chunk)
        print(f"[✓] b = {b}")
        secret_point = scalar_mul(P, b)

    print("[*] Computing shared secret S …")
    Sx_norm, Sy_norm = to_affine(secret_point)

    # Back to the original (non-normalised) model used on the wire
    Sx = (Sx_norm * c) % p
    Sy = (Sy_norm * c) % p
    print(f"[Sx] {Sx:064x}")
    print(f"[Sy] {Sy:064x}")

    key = sha256(Sx.to_bytes(32, "big") + Sy.to_bytes(32, "big")).digest()
    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)

    try:
        decoded = pt.decode("utf-8")
    except UnicodeDecodeError:
        decoded = pt.decode("utf-8", "ignore")

    print("\n[PLAINTEXT]")
    print(decoded)
    if "SHLK{" in decoded:
        start = decoded.index("SHLK{")
        end = decoded.index("}", start) + 1
        print(f"[FLAG] {decoded[start:end]}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
