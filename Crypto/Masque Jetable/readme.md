## Masque Jetable – write‑up
=========================

------
## Énoncé
Nous avons intercepté une communication utilisant des clés parfaitement aléatoires. Nous ne comprenons pas comment ces clés sont partagées avec le destinataire.

Il est possible qu'une transmission quantique soit en jeu.

7933b1a62867659c81d2363020621727012e283b7268982de652f8002c04dba7 main.rs.patch (246 bytes)

5285cfc6a843fde973ef80983e03f0d3a5f251a4efd42e938353ef6abe5f598f masque_jetable_player.tar.gz (1798 bytes)
nc challenges.shutlock.fr 50011 

## Mode opératoire
Un binaire Rust génère un paquet de 48 octets hex à chaque ligne. Le flag (longueur 42) est inséré à un offset aléatoire entre 0 et 5. Chaque octet clair `m` est chiffré par `c = key[m]`, où `key` est une permutation aléatoire de 0..255 **sans point fixe** (dérangement). La clé est régénérée à chaque ligne.

## Idée de l’attaque
-----------------
* Chaque position du paquet ne voit que 6 octets du flag au maximum (fenêtre de taille 6 à cause de l’offset 0..5).
* Pour une position donnée et beaucoup d’échantillons, l’octet du flag absent de la clé (car key[m] ≠ m pour tout m) sera légèrement **sous‑représenté** par rapport aux octets aléatoires.
* En prenant les `k` octets les moins fréquents à une position `p`, où `k` est le nombre d’indices de flag pouvant tomber sur `p`, on obtient l’ensemble `S[p]` des candidats plausibles pour la fenêtre se terminant en `p`.
* Les fenêtres glissent : `S[p]` et `S[p-1]` partagent 5 octets, le sixième « sort » (donne le caractère en position `p-6`), et un nouveau « entre » (donne le caractère en position `p`). Enchaîner ces différences reconstruit presque tout le flag.
* Les quelques ambiguïtés restantes se lèvent en imposant : unicité des octets, appartenance à l’ASCII imprimable, et compatibilité avec les ensembles de suffixe `S[42..47]`.

## Solveur `solver.py`
-------------------
* Capture N paquets (`--packets 200000` par défaut) sur `nc challenges.shutlock.fr 50011` et compte les fréquences par position (pickle `counts.pkl` pour éviter de refaire la capture).
* Construit `S[p]` avec les `k` octets les moins fréquents à chaque position.
* Calcule les ensembles « leave » / « enter » issus des intersections de fenêtres.
* Résout par backtracking contraint (ASCII imprimable, octets uniques, fenêtres compatibles) et vérifie les suffixes.
* Affiche le flag.

## Flag
----
`SHLK{d9gx73u65ak2le8zfojyqwpn04rbvcts1mhi}`

## Usage
-----
```
python3 solver.py --packets 200000       # capture + solve
python3 solver.py --counts counts.pkl    # réutilise les comptages
```

## Remarques
---------
* Le besoin en paquets vient du biais très faible introduit par l’absence de points fixes dans la clé : ~200k lignes donnent des ensembles stables et un flag unique.
* Les premiers octets (S,H,L,K,{,d) et le suffixe (…mhi) sont fortement contraints par les différences de fenêtres et les ensembles de fin `S[42..46]`.
