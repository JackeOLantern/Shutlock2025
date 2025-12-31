import glob, re, json, sys
pat = re.compile(r"40([0-9a-f]{128})40([0-9a-f]{128})([0-9a-f]{32})([0-9a-f]{32,})")
best=None
for path in sorted(glob.glob("streams/*.hex")):
    hx=open(path,"r",errors="ignore").read().strip()
    m=pat.search(hx)
    if not m: 
        continue
    P,Q,IV,C = m.group(1), m.group(2), m.group(3), m.group(4)
    cand={"path":path,"PX":P[:64],"PY":P[64:],"QX":Q[:64],"QY":Q[64:],"IV":IV,"CIPH":C}
    if best is None or len(C)>len(best["CIPH"]):
        best=cand
if not best:
    print("{}", end="")
    sys.exit(0)
print(json.dumps(best, indent=2))
