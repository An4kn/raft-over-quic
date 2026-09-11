#!/usr/bin/env python3
"""Rozklad odstepow miedzy komunikatami od lidera u followerow (linie FGAP) i heartbeaty
z osobnego watku (linie HBSTAT) - wariant HB_THREAD (HB-THREAD-CHANGES.md).

Wejscie: pliki z liniami "FGAP <id> <ms> <typ>" i "HBSTAT <follower> <count> <sumNs>" wyciete
z logow serwerow, np. zebrane tak:
  for h in dcc-1 dcc-2 dcc-6 dcc-7 dcc-8; do for t in quic tcp; do
    ssh $h "grep -h '^FGAP\\|^HBSTAT' /data/$USER/raft/$t/n5/server*.log" > fgap/${t}_$h.txt
  done; done
Transport rozpoznawany z nazwy pliku (quic_* / tcp_*). Uzycie: fgap_stats.py fgap/*.txt
"""
import sys, os, re, statistics

def pct(xs, p):
    if not xs: return float('nan')
    xs = sorted(xs); k = max(0, min(len(xs) - 1, int(round(p / 100.0 * (len(xs) - 1)))))
    return xs[k]

by_tr = {}      # transport -> list of gaps (ms)
by_tr_node = {} # (transport, file) -> gaps
hb = {}         # transport -> {follower: (count, sumNs)} (last HBSTAT line = cumulative)
for path in sys.argv[1:]:
    name = os.path.basename(path)
    tr = 'quic' if name.lower().startswith('quic') else ('tcp' if name.lower().startswith('tcp') else 'other')
    gaps = []
    with open(path, encoding='utf-8', errors='ignore') as fh:
        for line in fh:
            f = line.split()
            if len(f) >= 3 and f[0] == 'FGAP':
                try: gaps.append(float(f[2]))
                except ValueError: pass
            elif len(f) >= 4 and f[0] == 'HBSTAT':
                try: hb.setdefault(tr, {})[f[1]] = (int(f[2]), int(f[3]))
                except ValueError: pass
    by_tr.setdefault(tr, []).extend(gaps)
    by_tr_node[(tr, name)] = gaps

print(f"{'transport':10} {'plik':28} {'n':>7} {'mediana':>8} {'p90':>8} {'p99':>8} {'max':>8} {'>75ms':>7} {'>150ms':>7}")
for (tr, name), g in sorted(by_tr_node.items()):
    if not g: continue
    print(f"{tr:10} {name[:28]:28} {len(g):7d} {statistics.median(g):8.1f} {pct(g,90):8.1f} {pct(g,99):8.1f} {max(g):8.1f} "
          f"{100*sum(1 for x in g if x>75)/len(g):6.1f}% {100*sum(1 for x in g if x>150)/len(g):6.1f}%")
print()
for tr, g in sorted(by_tr.items()):
    if not g: continue
    print(f"RAZEM {tr:6} n={len(g)} mediana={statistics.median(g):.1f} p90={pct(g,90):.1f} p99={pct(g,99):.1f} "
          f"max={max(g):.1f} >75ms={100*sum(1 for x in g if x>75)/len(g):.1f}% >150ms={100*sum(1 for x in g if x>150)/len(g):.1f}%")
for tr, d in sorted(hb.items()):
    tot = sum(c for c, _ in d.values()); ns = sum(s for _, s in d.values())
    print(f"HBSTAT {tr:6} heartbeatow z watku (skumulowane, wszyscy followerzy): {tot}, sredni RTT {ns/tot/1e6 if tot else float('nan'):.2f} ms, followerzy: {', '.join(sorted(d))}")
