#!/usr/bin/env bash
#
# Scala JEDEN punkt pomiarowy (run_id, rep, transport, N, payload, conn) z wielu procesow
# RaftBench (po jednym na wezel kliencki) w JEDEN wiersz $RESULTS/wyniki.csv.
#
# Dlaczego nie zwykle sklejenie CSV: percentyli i odchylenia NIE wolno usredniac miedzy
# procesami. Statystyki opoznien licza sie tu z POLACZONEJ puli surowych probek (pliki
# lat_*.txt - zostaja na stale jako material zrodlowy), przepustowosc to suma przepustowosci
# procesow (kazdy mierzy wlasne okno na wlasnym zegarze, wiec suma nie wymaga synchronizacji
# zegarow miedzy wezlami), a liczniki kontrolne to zwykle sumy.
#
# Wejscie: point_*.env wypisany przez run_lan.sh (finish_point). Env niesie tez delty
# licznikow serwerowych: ELECTIONS (przejscia "to LEADER" z logow) i HOP_SS_* (RTT
# AppendEntries lider->follower z linii HOPSTAT, tylko RPC z danymi).
#
# Uzycie:
#   bash scal.sh <sciezka do point_*.env>
#   for f in ~/raft-results/<RUN>/point_*.env; do bash scal.sh "$f"; done   # offline
# Ponowne scalenie punktu NADPISUJE jego wiersz - nie dubluje. Klucz wiersza:
# (run_id, layout, rep, transport, N, payload, conn); seq/block opisuja wykonanie i kluczem
# nie sa. Envy z run_matrix.sh niosa tez SEQ/BLOCK/LAYOUT; stare z run_lan.sh dostaja "-".
set -euo pipefail

ENVF="${1:?uzycie: scal.sh <point.env>}"
RESULTS="$(cd "$(dirname "$ENVF")" && pwd)"
# shellcheck disable=SC1090
source "$ENVF"
# Nazwa scalonego pliku: domyslnie wyniki.csv, WYNIKI_CSV=wyniki2.csv daje inna
# (np. osobny plik dla przebiegu z REPEATS=3). Kolumna rep numeruje powtorzenia.
WYNIKI_CSV="${WYNIKI_CSV:-wyniki.csv}"
OUT="$RESULTS/$WYNIKI_CSV"

# Kolumny kolejnosci wykonania (run_matrix.sh): seq = numer punktu w przebiegu (sortowanie
# po seq = chronologia), block = <nr>-<transport> (jeden cykl zycia serwerow; QUIC i TCP
# ida w osobnych blokach), layout = uklad workerow po wezlach ("1-1-1-1-1"). Stare envy
# z run_lan.sh ich nie maja - dostaja wartosci neutralne.
SEQ="${SEQ:-0}"
BLOCK="${BLOCK:--}"
LAYOUT="${LAYOUT:--}"

HDR="run_id,seq,block,layout,rep,transport,cluster_size,payload_bytes,conn,clients_total,client_nodes,requests_per_client,warmup,mode,commit_mean_ms,commit_p50_ms,commit_stddev_ms,commit_p99_ms,commit_tput_req_s,duration_s,point_wall_s,requests_sent,requests_committed,requests_failed,conn_failed,elections,read_mean_ms,read_p50_ms,read_stddev_ms,read_p99_ms,read_tput_req_s,reads_ok,reads_failed,hop_client_leader_ms,hop_server_server_ms,hop_leader_client_ms,candidate_attempts"

# payload w bajtach - ta sama arytmetyka co RaftBench.parseSize (1kB=1024, 1MB=1024*1024)
PB=$(awk -v s="$PAYLOAD" 'BEGIN{ s=tolower(s)
  if (s ~ /mb$/)      { sub(/mb$/,"",s); printf "%d\n", s*1024*1024 }
  else if (s ~ /kb$/) { sub(/kb$/,"",s); printf "%d\n", s*1024 }
  else if (s ~ /b$/)  { sub(/b$/,"",s);  printf "%d\n", s }
  else                { printf "%d\n", s } }')

# ---- 1. wiersze CSV tego punktu (liczniki + tput per proces) ----
# Indeksy kolumn brane Z NAGLOWKA pliku (po nazwie), nie na sztywno - naglowek RaftBench
# moze rosnac na koncu bez psucia tego skryptu.
ROWS="$(mktemp)"; trap 'rm -f "$ROWS"' EXIT
first_hdr=""
for f in "$RESULTS"/$CSV_GLOB; do
  [ -f "$f" ] || continue
  [ -n "$first_hdr" ] || first_hdr="$(head -1 "$f")"
  awk -F, -v run="$RUN_ID" -v rep="$REP" -v tr="$T" -v n="$N" -v conn="$CONN" -v pb="$PB" '
    NR==1 { for(i=1;i<=NF;i++) ix[$i]=i; next }
    $ix["run_id"]==run && $ix["rep"]==rep && $ix["transport"]==tr \
      && $ix["cluster_size"]==n && $ix["conn"]==conn && $ix["mode"]=="rywrites" \
      && $ix["payload_bytes"]==pb { print }
  ' "$f" | tail -1 >> "$ROWS"
done

SUMS=$( { echo "$first_hdr"; cat "$ROWS"; } | awk -F, '
  NR==1 { for(i=1;i<=NF;i++) ix[$i]=i; next }
  NF>1 {
    sent += $ix["requests_sent"];      comm  += $ix["requests_committed"]
    fail += $ix["requests_failed"];    cf    += $ix["conn_failed"]
    rok  += $ix["reads_ok"];           rfail += $ix["reads_failed"]
    wt   += $ix["write_tput_req_s"];   rt    += $ix["read_tput_req_s"]
    tot  += $ix["total"];              nodes += 1
    if ($ix["duration_s"] > dmax) dmax = $ix["duration_s"] }
  END{ printf "%d %d %d %d %d %d %.1f %.1f %.3f %d %d\n",
       sent+0, comm+0, fail+0, cf+0, rok+0, rfail+0, wt+0, rt+0, dmax+0, tot+0, nodes+0 }')
read -r SENT COMM FAIL CF ROK RFAIL WTPUT RTPUT DMAX TOT NODES <<<"$SUMS"

# ---- 2. statystyki opoznien z POLACZONEJ puli probek wszystkich wezlow ----
stat_pool() {   # $1 = znacznik linii (w|r) ; echo -> "mean p50 stddev p99"
  cat "$RESULTS"/$LAT_GLOB 2>/dev/null | awk -v tag="$1" '$1==tag{print $2}' | sort -n | awk '
    { a[NR] = $1 }
    END{
      n = NR
      if (n == 0) { print "0 0 0 0"; exit }
      s = 0; for (i = 1; i <= n; i++) s += a[i]; m = s / n
      ss = 0; for (i = 1; i <= n; i++) { d = a[i] - m; ss += d * d }
      sd = n > 1 ? sqrt(ss / (n - 1)) : 0
      # ta sama formula co RaftBench.percentileMs: idx = round(p/100*(n-1)), 0-based
      i50 = int(0.50 * (n - 1) + 0.5) + 1; if (i50 > n) i50 = n
      i99 = int(0.99 * (n - 1) + 0.5) + 1; if (i99 > n) i99 = n
      printf "%.3f %.3f %.3f %.3f\n", m/1e6, a[i50]/1e6, sd/1e6, a[i99]/1e6
    }'
}
read -r WMEAN WP50 WSD WP99 <<<"$(stat_pool w)"
read -r RMEAN RP50 RSD RP99 <<<"$(stat_pool r)"

# hop klient<->lider: srednie z puli probek sond wszystkich procesow (c2l=$3, l2c=$4)
read -r HC2L HL2C <<<"$(cat "$RESULTS"/$LAT_GLOB 2>/dev/null | awk '
  $1=="hop"{ c += $3; l += $4; n++ }
  END{ if (n == 0) print "0 0"; else printf "%.3f %.3f\n", c/n/1e6, l/n/1e6 }')"

# hop serwer<->serwer: delta HOPSTAT z env (suma_ns/count -> ms)
HSS=$(awk -v c="${HOP_SS_COUNT:-0}" -v s="${HOP_SS_SUM_NS:-0}" \
  'BEGIN{ printf "%.3f\n", (c > 0) ? s / c / 1e6 : 0 }')

ROW="$RUN_ID,$SEQ,$BLOCK,$LAYOUT,$REP,$T,$N,$PB,$CONN,$TOT,$NODES,$REQUESTS,$WARMUP,rywrites,$WMEAN,$WP50,$WSD,$WP99,$WTPUT,$DMAX,${POINT_WALL_S:-0},$SENT,$COMM,$FAIL,$CF,${ELECTIONS:-0},$RMEAN,$RP50,$RSD,$RP99,$RTPUT,$ROK,$RFAIL,$HC2L,$HSS,$HL2C,${CANDIDATES:-0}"

# Tworzenie pliku: najpierw naglowek opisowy (linie "# ..." od run_matrix.sh - mowia, czego
# plik dotyczy), potem wiersz nazw kolumn. Czytanie: pandas.read_csv(f, comment='#') albo
# grep -v '^#'. Gdy plik istnieje, ale ma INNY uklad kolumn (np. stary format sprzed
# seq/block/layout), odkladamy go na bok zamiast mieszac formaty w jednym pliku.
if [ -f "$OUT" ]; then
  CUR_HDR="$(grep -v '^#' "$OUT" | head -1 || true)"
  if [ "$CUR_HDR" != "$HDR" ]; then
    mv "$OUT" "$OUT.stary-format.$(date +%s)"
    echo "uwaga: $WYNIKI_CSV mial inny uklad kolumn - odlozony jako $(basename "$OUT").stary-format.*"
  fi
fi
if [ ! -f "$OUT" ]; then
  { [ -f "$RESULTS/naglowek.txt" ] && cat "$RESULTS/naglowek.txt"; echo "$HDR"; } > "$OUT"
fi
# Nadpisanie wiersza o tym samym kluczu (run_id,layout,rep,transport,N,payload,conn) -
# ponowne scalenie nie dubluje. seq/block to opis wykonania, NIE czesc klucza, dlatego
# w ich pozycjach wzorca stoi [^,]*. Bez layoutu w kluczu dwa uklady o tych samych
# pozostalych parametrach kasowalyby sobie nawzajem wiersze.
grep -v "^$RUN_ID,[^,]*,[^,]*,$LAYOUT,$REP,$T,$N,$PB,$CONN," "$OUT" > "$OUT.tmp" || true
mv "$OUT.tmp" "$OUT"
echo "$ROW" >> "$OUT"
echo "$WYNIKI_CSV <- $ROW"
