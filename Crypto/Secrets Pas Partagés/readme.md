## Présentation (énoncé)
Secrets Pas Partagés
500

Lors de vos investigations, vous tombez sur un trafic chiffré qui semble procéder à un échange de clés avant de transmettre des données secrètes.

L'une de vos sources a réussi à mettre la main sur un extrait de documentation concernant ce mystérieux protocole.

Saurez-vous trouver l'information secrète ?

57857c03107f08dd224f2ed34084cc4a7af6f5f4e1b074791bac8315e80c3a0c capture.pcap (119752 bytes)
0719272105e0a6fca92020e86664316a3762c793b9698bbddc33aef74f653584 DOCUMENTATION.md (1731 bytes)

## Write-up (résumé)

- Le protocole DHutlock utilise une courbe Edwards tordue : `x² + y² = c² (1 + d x² y²)`, puis normalisée en `a=1` avec `d' = d·c⁴`. Les points publiés dans le PCAP sont P=a·G et Q=b·G.
- L’ordre de G est intégralement factorisable :  
  ord(G) = 2² · 5 · 52 579 · 55 763 · 101 837 · 33 086 773 · 1 663 966 639 · 7 878 749 717 · 183 678 983 · 7 094 429 431 169 · 17 107 097 727 061.  
  Un Pohlig–Hellman avec BSGS batched sur chaque facteur donne b tel que Q = b·G.
- Le secret partagé est S = b·P. Les coordonnées doivent être re-projetées sur le modèle d’origine en multipliant par `c` avant la KDF, sinon on obtient un mauvais texte clair.
- KDF du protocole : `K = SHA256(Sx || Sy)` (big endian, coordonnées dénormalisées). Le déchiffrement AES-CBC (IV fourni dans le flux) révèle le secret ASCII.

Flag obtenu :

```
SHLK{cd56033a9b9728bd7d60f7c4b10479b5}
```

## Démarche (DOC + PCAP)

- `DOCUMENTATION.md` fixe p, le format 0x40 || X || Y et la KDF SHA256(Sx||Sy) → AES-CBC(IV).
- `capture.pcap` → `streams/capture.pcap.0.hex` / `pqivc.json` (P, Q, IV, CIPH) :  
  PX=c99c…d961, PY=0629…4503, QX=7552…2b27, QY=090a…df89, IV=0344ef7ad39239f379ca63bd7bf5bb45, CIPH=9130…9047a.
- Avec P et Q (cf. Secrets_pas_partages_2.docx), résolution de la forme Edwards minimale `x² + y² = C + D x² y²` :  
  C = c² = 0xe434305b206595acc63ffbb52f912d310d0e19cb1ff87d27b67e797fceed42fb,  
  D = c²d = 0xb23bc9ed54d55fdf4f532ffaa96238d08d2e3560bd2a09552054103f128e241c, d = D·C⁻¹ mod p, c = sqrt(C). Tous les points (PCAP + exemple DOC) vérifient `x² + y² = c² (1 + d x² y²)`.
- L’exemple chiffré du DOC fournit un (a, P)/(b, Q) cohérent ; le dlog de cet exemple donne un `a` utilisable pour sauter le dlog sur notre capture (`--scalar-on Q --scalar …`), sinon PH+BSGS retrouve `b` directement.
- Secret partagé : S = a·Q (= b·P), dénormalisé par `c`, KDF SHA256(Sx||Sy), puis AES-CBC avec IV du flux → flag ci-dessus.

## Pièges et erreurs rencontrés

- Oubli de la dénormalisation : utiliser directement `Sx_norm, Sy_norm` (points divisés par c) dans la KDF produit un texte illisible. Il fallait multiplier par `c` pour revenir au modèle “doc”.
- Mauvais mapping Edwards → Montgomery : certaines variantes de la birationnelle ne remettaient pas les points sur la courbe, menant à des logs discrets impossibles. La version avec `u=(1+y)/(1-y)` et yM=sqrt(B)*v est la bonne ici.
- Factorisation incomplète : se contenter de la partie lisse (≤2e6) laisse un résidu énorme, et un `discrete_log` plein échoue/tourne longtemps. La factorisation complète de ord(G) (pre-computée) est nécessaire pour PH.
- BSGS sans batch d’inversions : la version naïve explosait en mémoire/temps sur les facteurs ~10¹³–10¹⁴. Le batching (inversions en O(n)) rend le BSGS praticable.
- Mélange des endianess : tester les KDF en little-endian ou inverser l’ordre des coordonnées ne donnait rien. La doc précise SHA256(Sx||Sy) big-endian : respecter strictement cet ordre.

## Usage du solveur

1. Vérifier que `pqivc.json` (extrait de `capture.pcap`) est présent.
2. Par défaut (rapide, sans dlog) :  
   `python3 solver.py`  
   → utilise le scalaire client `a` retrouvé depuis l’exemple du DOC et calcule directement le secret.
3. Pour injecter un scalaire spécifique :  
   `python3 solver.py --scalar <n> --scalar-on P|Q`
4. Pour forcer le calcul complet PH+BSGS du dlog (plus long) :  
   `python3 solver.py --force-dlog --verbose`

Options utiles : `--pqivc` (chemin), `--chunk` (taille de batch BSGS), `-v/--verbose` (progression). Aucune dépendance externe hors `pycryptodome` (Crypto) n’est nécessaire.

## Chaîne complète depuis capture.pcap

1. Reconstituer le flux hex depuis le PCAP (si absent) :  
   `tcpflow -r capture.pcap -o tcpflows`  
   `./reassemble.sh > streams/capture.pcap.0.hex`   (ou équivalent pour concaténer les flux et produire une ligne hex)
2. Extraire P, Q, IV, CIPH :  
   `python3 extract_points_and_cipher.py capture.pcap`  
   (ou `python3 extract.py > pqivc.json` si déjà en hex)  
   → obtenir `pqivc.json` (PX/PY/QX/QY/IV/CIPH)
3. Résoudre et récupérer le flag :  
   - Rapide : `python3 solver.py`  
   - Complet PH+BSGS : `python3 solver.py --force-dlog --verbose`
