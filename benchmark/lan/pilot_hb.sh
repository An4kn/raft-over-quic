#!/usr/bin/env bash
#
# PILOT (~15 min w rezerwacji 30 min): czy przy krotkim limicie elekcji TCP produkuje proby
# elekcji, a QUIC z pieciu strumieniami nie, i czy roznice robia strumienie (kontrola: QUIC
# z JEDNYM strumieniem). Trzy warianty po JEDNYM punkcie: 1 MB, conn B, uklad LAYOUT
# (domyslnie "6 6 6 6 6" = 30 workerow, najwieksze paczki), wszystkie z watkiem heartbeatow
# (HB_THREAD=1) i limitem elekcji RPC_TIMEOUT (domyslnie 100,200 ms; heartbeat co MIN/2):
#   tcp     - TCP z TLS
#   quic    - QUIC, piec strumieni na polaczenie serwer-serwer
#   quic1s  - QUIC, jeden strumien (QUIC_SINGLE_STREAM=1) - ta sama biblioteka, ten sam
#             nadawca, inny tylko uklad strumieni
# Kazdy wariant to osobne wywolanie run_matrix.sh z wlasnym RUN_ID (pilot_<ts>_<wariant>),
# po nim zbior linii FGAP/HBSTAT z logow serwerow (zanim nastepny wariant je nadpisze).
# Na koncu tabela: przepustowosc, p99, RTT AppendEntries, elections, candidate_attempts,
# oraz rozklad odstepow miedzy komunikatami od lidera u followerow (FGAP).
#
# Wymaga (jak run_matrix.sh): ~/ratis.jar z HB-THREAD-CHANGES.md, ~/run_matrix.sh, ~/scal.sh,
# ~/log4j.properties (bez niego elections/candidate_attempts = 0), zywa rezerwacja -N 10.
#
#   salloc --no-shell -p dcc -N 10 -t 00:30:00
#   bash ~/pilot_hb.sh
#   REQ=40 LAYOUT="4 4 4 4 4" bash ~/pilot_hb.sh        # krocej, 20 workerow
#   RPC_TIMEOUT=60,120 bash ~/pilot_hb.sh               # ostrzejszy limit
#   NO_PREVOTE=1 bash ~/pilot_hb.sh                     # klasyczny Raft: proby obalaja lidera
#   VARIANTS="tcp quic" bash ~/pilot_hb.sh              # bez kontroli jednostrumieniowej
#   HB_THREAD=0 bash ~/pilot_hb.sh                      # ten sam pilot bez watku heartbeatow
#   RAM_LOG=1 REQ=40 bash ~/pilot_hb.sh                 # ten sam pilot BEZ zapisu na dysk (tmpfs)
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RM="$HERE/run_matrix.sh"
[ -f "$RM" ] || { echo "!! brak $RM obok pilot_hb.sh"; exit 1; }
[ -f "$HOME/log4j.properties" ] || echo "!! UWAGA: brak ~/log4j.properties - elections i candidate_attempts wyjda 0"

TS="$(date +%Y%m%d_%H%M%S)"
PILOT="${PILOT:-pilot_$TS}"
VARIANTS="${VARIANTS:-tcp quic quic1s}"
# RAM_LOG=1: ten sam pilot BEZ zapisu na dysk (storage serwerow na tmpfs, jak w wariancie
# kontrolnym run_matrix.sh). 1 MB jest tam domyslnie zablokowane (GB logu), wiec pilot sam
# ustawia RAM_LOG_ALLOW_1MB=1 - log punktu to ok. (REQ+WARMUP) x workerow MB, przy REQ=60
# i 30 workerach ok. 2 GB; musi sie zmiescic w wolnym tmpfs (run_matrix.sh sprawdza
# RAM_LOG_MIN_MB). Sciezka logow serwerow brana z meta.txt (storage_root=...).
RAM_LOG="${RAM_LOG:-0}"; export RAM_LOG
[ "$RAM_LOG" = 1 ] && export RAM_LOG_ALLOW_1MB="${RAM_LOG_ALLOW_1MB:-1}"

export SIZES=5
export NUM_CLIENT_NODES="${NCLI:-5}"
export SERVER_NODES="${SERVER_NODES:-}" CLIENT_NODES="${CLIENT_NODES:-}"
export PAYLOADS=1MB CONNS=B
export CLIENT_LAYOUTS="\"${LAYOUT:-6 6 6 6 6}\""
export REQUESTS="${REQ:-60}" WARMUP="${WARMUP:-5}" REPEATS=1
export HB_THREAD="${HB_THREAD:-1}" FGAP_MS="${FGAP_MS:-20}"
export RPC_TIMEOUT="${RPC_TIMEOUT:-100,200}" NO_PREVOTE="${NO_PREVOTE:-0}"
export JAVA="${JAVA:-$HOME/jdk21/bin/java -Dlog4j.configuration=file:$HOME/log4j.properties}"
export BENCH_TIMEOUT="${BENCH_TIMEOUT:-600}"

echo "=================================================================================="
echo " PILOT $PILOT: 1 MB, conn B, uklad ${LAYOUT:-6 6 6 6 6}, $REQUESTS zadan/klienta, warmup $WARMUP"
echo " hb_thread=$HB_THREAD  rpc_timeout=$RPC_TIMEOUT  no_prevote=$NO_PREVOTE  fgap_ms=$FGAP_MS  storage: $([ "$RAM_LOG" = 1 ] && echo 'tmpfs (BEZ zapisu na dysk)' || echo 'dysk (/data)')"
echo " opcje serwera (SERVER_JAVA_OPTS): ${SERVER_JAVA_OPTS:-brak (paczka 4MB domyslna)}"
echo " warianty: $VARIANTS  (kazdy: start klastra ~70-90 s + jeden punkt ~3-4 min)"
echo " wyniki: ~/raft-results/${PILOT}_<wariant>/  (wyniki.csv, fgap/)"
echo "=================================================================================="

for v in $VARIANTS; do
  case "$v" in
    tcp)    TR=tcp;  SS=0 ;;
    quic)   TR=quic; SS=0 ;;
    quic1s) TR=quic; SS=1 ;;
    *) echo "!! nieznany wariant '$v' (tcp | quic | quic1s)"; exit 1 ;;
  esac
  export RUN_ID="${PILOT}_${v}" TRANSPORTS="$TR" QUIC_SINGLE_STREAM="$SS"
  echo
  echo "=== WARIANT $v: transport=$TR single_stream=$SS -> ~/raft-results/$RUN_ID   ($(date +%H:%M:%S))"
  bash "$RM" || echo "!! run_matrix.sh zakonczyl sie bledem dla wariantu $v (szczegoly wyzej)"
  R="$HOME/raft-results/$RUN_ID"
  pool="$(sed -n 's/^server_pool=//p' "$R/meta.txt" 2>/dev/null)"
  sroot="$(sed -n 's/.*storage_root=//p' "$R/meta.txt" 2>/dev/null | head -1)"; sroot="${sroot:-/data}"
  mkdir -p "$R/fgap"
  for h in $pool; do
    ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$h" \
      "grep -h '^FGAP\|^HBSTAT' '$sroot/$USER/raft/$TR/n5/'server*.log 2>/dev/null" \
      > "$R/fgap/${TR}_$h.txt" 2>/dev/null || true
  done
  echo "    FGAP/HBSTAT: $(cat "$R"/fgap/*.txt 2>/dev/null | wc -l | tr -d ' ') linii z wezlow: $pool"
done

# ---------------- podsumowanie ----------------
summ() {   # $1=wyniki.csv $2=etykieta
  awk -F, -v L="$2" '
    /^#/ { next }
    !h   { for (i = 1; i <= NF; i++) ix[$i] = i; h = 1; next }
    {
      ca = ("candidate_attempts" in ix) ? $ix["candidate_attempts"] : "-"
      printf "%-8s %-8s %9.1f %10.0f %10.0f %9.0f %8d %12s\n", L, $ix["transport"],
        $ix["commit_tput_req_s"], $ix["commit_p99_ms"], $ix["read_p99_ms"],
        $ix["hop_server_server_ms"], $ix["elections"], ca
    }' "$1"
}
fgap_summ() {   # pliki fgap
  cat "$@" 2>/dev/null | awk '$1 == "FGAP" { print $3 }' | sort -n | awk '
    { a[NR] = $1 }
    END {
      if (NR == 0) exit
      n = NR; c75 = 0; c150 = 0
      for (i = 1; i <= n; i++) { if (a[i] > 75) c75++; if (a[i] > 150) c150++ }
      p50 = a[int((n + 1) / 2)]; p90 = a[int(n * 0.9) < 1 ? 1 : int(n * 0.9)]; p99 = a[int(n * 0.99) < 1 ? 1 : int(n * 0.99)]
      printf "    FGAP u followerow: n=%d mediana=%.0f ms p90=%.0f p99=%.0f max=%.0f  >75ms=%.1f%%  >150ms=%.1f%%\n",
        n, p50, p90, p99, a[n], 100 * c75 / n, 100 * c150 / n
    }'
  cat "$@" 2>/dev/null | awk '$1 == "HBSTAT" { c[$2] = $3; s[$2] = $4 }
    END { C = 0; S = 0; for (k in c) { C += c[k]; S += s[k] }
          if (C > 0) printf "    HBSTAT (lider): %d heartbeatow z watku, sredni RTT %.2f ms\n", C, S / C / 1e6
          else print "    HBSTAT: brak (watek heartbeatow nie wyslal nic - HB_THREAD=0 albo blad)" }'
}

echo
echo "=================== PODSUMOWANIE PILOTA $PILOT ($(date +%H:%M:%S)) ==================="
echo " limit elekcji $RPC_TIMEOUT ms, heartbeat co $(( ${RPC_TIMEOUT%%,*} / 2 )) ms, pre-vote $([ "$NO_PREVOTE" = 1 ] && echo WYLACZONE || echo wlaczone), watek heartbeatow $HB_THREAD, storage $([ "$RAM_LOG" = 1 ] && echo tmpfs || echo dysk)"
echo " opcje serwera (SERVER_JAVA_OPTS): ${SERVER_JAVA_OPTS:-brak (paczka 4MB domyslna)}"
printf '%-8s %-8s %9s %10s %10s %9s %8s %12s\n' wariant transp zapisy/s p99zap_ms p99odcz_ms rttAE_ms elekcje kandydatury
for v in $VARIANTS; do
  f="$HOME/raft-results/${PILOT}_${v}/wyniki.csv"
  if [ -f "$f" ]; then summ "$f" "$v"; else printf '%-8s brak wyniki.csv\n' "$v"; fi
done
echo
for v in $VARIANTS; do
  echo "--- $v ---"
  fgap_summ "$HOME/raft-results/${PILOT}_${v}"/fgap/*.txt
done
echo
echo "Odczyt: kandydatury = przejscia FOLLOWER->CANDIDATE (proby elekcji); elekcje = nowi liderzy."
echo "Oczekiwanie: tcp i quic1s > 0 kandydatur i FGAP z ogonem > limitu; quic = 0 i FGAP <= ~2x odstep heartbeatu."
echo "Pelne dane: ~/raft-results/${PILOT}_*/ (wyniki.csv, point_*.env, fgap/)."
