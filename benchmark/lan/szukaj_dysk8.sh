#!/usr/bin/env bash
#
# SZUKANIE PUNKTU (ok. 1,5-2 h, rezerwacja 2,5 h): na DYSKU, paczka 8 MB, 30 workerow x 1 MB,
# watek heartbeatow, pre-vote wlaczone - szuka limitu elekcji, przy ktorym TCP TRACI LIDERA,
# ALE DALEJ ZATWIERDZA ZAPISY (nie zapasc), a potem w tym punkcie robi QUIC (5 strumieni),
# QUIC z jednym strumieniem i dwa dodatkowe powtorzenia calej trojki.
#
# Znane z pilotow 10.09 (dysk, 8 MB): limit 150/300 -> TCP trzyma lidera (0 zmian, 2-11 prob);
# limit 100/200 -> TCP w zapasci (0 zapisow, 12 zmian). Szukamy pomiedzy: start 120/240, potem
# polowienie przedzialu (dead -> luzniej, 0 zmian -> ostrzej), maks. PROBES prob TCP-only.
#
#   salloc --no-shell -p dcc -N 10 -t 02:30:00      (wezly jak w pilotach)
#   nohup bash ~/szukaj_dysk8.sh > ~/szukaj_dysk8.log 2>&1 &
#   tail -f ~/szukaj_dysk8.log
#
# Zmienne (opcjonalne): START=120 PROBES=4 REPS=2 REQ=40 BENCH_TIMEOUT=300
#   SERVER_JAVA_OPTS="-Dratis.appender.buffer=8388600"  SERVER_NODES=...  CLIENT_NODES=...
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PH="$HERE/pilot_hb.sh"
[ -f "$PH" ] || { echo "!! brak $PH obok szukaj_dysk8.sh"; exit 1; }

export RAM_LOG=0 HB_THREAD=1 NO_PREVOTE=0
export REQ="${REQ:-40}" BENCH_TIMEOUT="${BENCH_TIMEOUT:-300}"
export SERVER_JAVA_OPTS="${SERVER_JAVA_OPTS:--Dratis.appender.buffer=8388600}"
export SERVER_NODES="${SERVER_NODES:-dcc-1 dcc-7 dcc-9 dcc-10 dcc-11}"
export CLIENT_NODES="${CLIENT_NODES:-dcc-12 dcc-13 dcc-14 dcc-15 dcc-16}"
START="${START:-120}"; PROBES="${PROBES:-4}"; REPS="${REPS:-2}"
LO="${LO:-100}"    # najwyzszy MIN, przy ktorym TCP byl w zapasci (znane: 100)
HI="${HI:-150}"    # najnizszy MIN, przy ktorym TCP mial 0 zmian lidera (znane: 150)
TS="$(date +%Y%m%d_%H%M%S)"
RES="$HOME/raft-results"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# odczyt jednego wyniki.csv: committed tput elections attempts (po nazwach kolumn)
read_csv() {
  awk -F, '
    /^#/ { next }
    !h   { for (i = 1; i <= NF; i++) ix[$i] = i; h = 1; next }
    { ca = ("candidate_attempts" in ix) ? $ix["candidate_attempts"] : 0
      printf "%d %.1f %d %d\n", $ix["requests_committed"], $ix["commit_tput_req_s"], $ix["elections"], ca; exit }
  ' "$1"
}

# tabela z kilku pilotow (jak w pilot_hb.sh) + FGAP/HBSTAT
row() {   # $1=wyniki.csv $2=etykieta
  awk -F, -v L="$2" '
    /^#/ { next }
    !h   { for (i = 1; i <= NF; i++) ix[$i] = i; h = 1; next }
    { ca = ("candidate_attempts" in ix) ? $ix["candidate_attempts"] : "-"
      printf "%-22s %-7s %9.1f %10.0f %10.0f %9.0f %8d %12s\n", L, $ix["transport"],
        $ix["commit_tput_req_s"], $ix["commit_p99_ms"], $ix["read_p99_ms"],
        $ix["hop_server_server_ms"], $ix["elections"], ca }' "$1"
}
fg() {    # $1=katalog pilota_wariant
  cat "$1"/fgap/*.txt 2>/dev/null | awk '$1 == "FGAP" { print $3 }' | sort -n | awk '
    { a[NR] = $1 }
    END { if (NR == 0) { print "      FGAP: brak"; exit }
      n = NR; c = 0; for (i = 1; i <= n; i++) if (a[i] > 150) c++
      p50 = a[int((n + 1) / 2)]; p90 = a[int(n * 0.9) < 1 ? 1 : int(n * 0.9)]; p99 = a[int(n * 0.99) < 1 ? 1 : int(n * 0.99)]
      printf "      FGAP n=%d p50=%.0f p90=%.0f p99=%.0f max=%.0f >150ms=%.1f%%", n, p50, p90, p99, a[n], 100 * c / n }'
  cat "$1"/fgap/*.txt 2>/dev/null | awk '$1 == "HBSTAT" { c[$2] = $3; s[$2] = $4 }
    END { C = 0; S = 0; for (k in c) { C += c[k]; S += s[k] }
          if (C > 0) printf "   HBSTAT %d hb, RTT %.1f ms\n", C, S / C / 1e6; else print "   HBSTAT brak" }'
}

run_pilot() {   # $1=PILOT $2=MIN $3=VARIANTS
  export PILOT="$1" RPC_TIMEOUT="$2,$(( 2 * $2 ))" VARIANTS="$3"
  log "PILOT $PILOT: limit $RPC_TIMEOUT, warianty: $VARIANTS"
  bash "$PH"
}

echo "=================================================================================="
echo " SZUKANIE $TS: dysk, $SERVER_JAVA_OPTS, REQ=$REQ, start MIN=$START, przedzial ($LO,$HI), maks. $PROBES prob"
echo " serwery: $SERVER_NODES | klienci: $CLIENT_NODES"
echo "=================================================================================="

FOUND=""; LASTWORK=""; PROBELOG=""
MIN="$START"
for ((p = 1; p <= PROBES; p++)); do
  PILOT="szukaj_${TS}_t${MIN}"
  run_pilot "$PILOT" "$MIN" "tcp"
  f="$RES/${PILOT}_tcp/wyniki.csv"
  if [ ! -f "$f" ]; then log "!! brak $f - run_matrix.sh nie dal wyniku (rezerwacja? wezly?). STOP."; exit 1; fi
  read -r committed tput elections attempts < <(read_csv "$f")
  log "TCP przy $MIN/$((2*MIN)): zatwierdzone=$committed, $tput zapisow/s, zmiany lidera=$elections, proby=$attempts"
  PROBELOG+="  MIN=$MIN: zatw=$committed tput=$tput zmiany=$elections proby=$attempts"$'\n'
  if [ "$committed" -eq 0 ]; then
    verdict="ZAPASC"; LO="$MIN"
  elif [ "$elections" -ge 1 ]; then
    verdict="ZNALEZIONO"; FOUND="$MIN"; LASTWORK="$MIN"
  else
    verdict="TRZYMA (0 zmian)"; HI="$MIN"; LASTWORK="$MIN"
  fi
  log "werdykt: $verdict  (przedzial teraz: zapasc<=$LO, trzyma>=$HI)"
  [ -n "$FOUND" ] && break
  next=$(( (LO + HI) / 2 )); next=$(( (next + 2) / 5 * 5 ))
  if [ "$next" -le "$LO" ] || [ "$next" -ge "$HI" ]; then log "przedzial wyczerpany"; break; fi
  MIN="$next"
done

if [ -z "$FOUND" ]; then
  if [ -n "$LASTWORK" ]; then
    MIN="$LASTWORK"; log "nie znaleziono punktu ze zmiana lidera i zapisami; biore ostatni dzialajacy: MIN=$MIN"
  else
    MIN="$HI"; log "TCP w zapasci we wszystkich probach; biore MIN=$HI (znany jako trzymajacy)"
    PILOT="szukaj_${TS}_t${MIN}"; run_pilot "$PILOT" "$MIN" "tcp"
  fi
fi
PILOT="szukaj_${TS}_t${MIN}"
run_pilot "$PILOT" "$MIN" "quic quic1s"
for ((r = 2; r <= REPS + 1; r++)); do
  run_pilot "szukaj_${TS}_t${MIN}_r${r}" "$MIN" "tcp quic quic1s"
done

echo
echo "=================== WYNIK SZUKANIA $TS ($(date +%H:%M:%S)) ==================="
echo " dysk, $SERVER_JAVA_OPTS, REQ=$REQ, pre-vote wlaczone, watek heartbeatow"
echo " proby TCP-only:"; printf '%s' "$PROBELOG"
echo " wybrany limit: $MIN/$((2*MIN)) ms $([ -n "$FOUND" ] && echo '(TCP: zmiany lidera > 0 i zapisy > 0)' || echo '(bez punktu spelniajacego oba warunki)')"
printf '%-22s %-7s %9s %10s %10s %9s %8s %12s\n' pilot transp zapisy/s p99zap_ms p99odcz_ms rttAE_ms elekcje kandydatury
for d in "$RES"/szukaj_${TS}_t${MIN}_tcp "$RES"/szukaj_${TS}_t${MIN}_quic "$RES"/szukaj_${TS}_t${MIN}_quic1s \
         "$RES"/szukaj_${TS}_t${MIN}_r*_tcp "$RES"/szukaj_${TS}_t${MIN}_r*_quic "$RES"/szukaj_${TS}_t${MIN}_r*_quic1s; do
  [ -f "$d/wyniki.csv" ] || continue
  lab="${d##*/}"; lab="${lab#szukaj_${TS}_}"
  row "$d/wyniki.csv" "$lab"; fg "$d"
done
echo "Pelne dane: ~/raft-results/szukaj_${TS}_*/"
