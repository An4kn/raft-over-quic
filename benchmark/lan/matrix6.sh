#!/usr/bin/env bash
#
# GOTOWA MACIERZ: uklady 1..6 workerow na wezel x conn A,B x payload 1B,1kB,1MB x QUIC,TCP,
# 1000 zadan na klienta. Naklada sie na run_matrix.sh - podaje mu parametry i TNIE calosc
# na kawalki, kazdy do osobnej rezerwacji SLURM, wszystkie do JEDNEGO wyniki.csv.
#
# ------------------------------------------------------------------------------------
# DLACZEGO KAWALKI
# Macierz to 72 punkty. Przy 1000 zadaniach 1MB jest droge i rosnie z liczba workerow:
# uklad "6 6 6 6 6" (30 workerow) to 30 000 zadan po 1MB przez konsensus, a lider
# wypycha to jeszcze x4 do followerow - jeden taki punkt trwa ~46 min NA TRANSPORT.
# Cala macierz to ~9 h czystego pomiaru. Rezerwacja DCC to 30 min, wiec skrypt liczy
# koszt kazdego punktu i pakuje punkty w kawalki mieszczace sie w zadanym budzecie
# (BUDGET_MIN, domyslnie 22 min pomiaru + zapas na start klastra).
#
# MODEL KOSZTU (skalibrowany na pelnej macierzy DCC 2026-08-28: 72 punkty, 2.9 h;
# grupa 1MB zmierzona 121 min vs model 111 min, grupy 1B/1kB po 22 min):
#   czas punktu = zadania x max(latencja_bazowa, workerow / max_przepustowosc)
# Zamkniete petle: dopoki klaster nie jest wysycony, rzadzi latencja; przy 1MB szybko
# wchodzi sufit pasma lidera (~13 zatwierdzen/s) i czas rosnie liniowo z liczba workerow.
# Kalibracje mozna nadpisac (LAT_*, TPUT_*) - patrz sekcja MODEL nizej.
# ------------------------------------------------------------------------------------
#
# UZYCIE
#   1. Plan calosci - nie dotyka klastra, nie potrzebuje rezerwacji:
#        bash ~/matrix6.sh plan
#      Wypisuje kawalki, czas kazdego i GOTOWA linie salloc z wymaganym -t.
#
#   2. Kawalek po kawalku (kazdy w swojej rezerwacji):
#        salloc --no-shell -p dcc -N 10 -t 00:30:00     # -t wg planu!
#        bash ~/matrix6.sh 1
#        scancel <jobid>
#
#   3. Kontynuacja po przerwie - RUN_ID jest zapamietany w ~/.matrix6-run i wszystkie
#      kawalki dopisuja do tego samego wyniki.csv. Jawnie:
#        RUN_ID=20260828_101500 bash ~/matrix6.sh 4
#
#   4. Mniejszy 1MB, zeby zmiescic sie w 30 min (ZALECANE, patrz plan):
#        REQ_1MB=200 bash ~/matrix6.sh plan
#
#   5. Doscalanie offline po sciagnieciu wynikow (bez klastra):
#        for f in ~/raft-results/<RUN_ID>/point_*.env; do bash ~/scal.sh "$f"; done
#
#   6. Wariant QUIC z JEDNYM strumieniem na polaczenie serwer-serwer (tylko QUIC, 36 pkt;
#      te same parametry co macierz, do porownania punkt w punkt po run_id):
#        QUIC_SINGLE_STREAM=1 TRANSPORT_LIST=quic REQ_1MB=200 bash ~/matrix6.sh plan
#        QUIC_SINGLE_STREAM=1 TRANSPORT_LIST=quic REQ_1MB=200 bash ~/matrix6.sh 1   # itd.
#      Wariant ma wlasna pamiec RUN_ID (~/.matrix6-run-1s) i sufiks "_1s" w RUN_ID.
#
#   7. Wariant KONTROLNY "log w pamieci" (RAM_LOG=1): storage serwerow na tmpfs (/dev/shm),
#      fsync natychmiastowy, bez trwalosci; OBA transporty, obciazenie jak w macierzy, ale
#      tylko 1B i 1kB (1MB to GB logu na punkt - nie zmiesci sie w RAM). 48 punktow.
#      Jedna komenda w tle, przy WLASNEJ rezerwacji (-N 10, -t wg planu):
#        RAM_LOG=1 bash ~/matrix6.sh plan
#        nohup env RAM_LOG=1 bash ~/matrix6.sh all > ~/matrix_ram.log 2>&1 &
#      Wariant ma wlasna pamiec RUN_ID (~/.matrix6-run_ram) i sufiks "_ram" w RUN_ID;
#      run_matrix.sh sprawdza tmpfs i wolne miejsce na wezlach serwerowych PRZED startem.
#
# WYMAGANIA na klastrze: ~/ratis.jar, ~/netty-quiche-linux.jar, ~/jdk21, ~/ratis-test/...ssl,
# ~/run_matrix.sh, ~/scal.sh, ~/log4j.properties (bez niego kolumna elections bedzie 0).
set -euo pipefail

# ---------------- CO MIERZYMY ----------------
# Wezly: domyslnie Z REZERWACJI (regula pozycyjna run_matrix.sh: ostatnie NCLI wezlow
# alokacji = klienci, reszta = serwery). Nazwy na sztywno tylko gdy podasz je jawnie:
#   CLIENT_NODES="dcc-6 dcc-7 dcc-8 dcc-9 dcc-10" SERVER_NODES="dcc-1 ... dcc-5"
# (sztywne domyslne dcc-9..13 wywalily przebieg, gdy SLURM dal dcc-1..10).
CLIENT_NODES="${CLIENT_NODES:-}"
SERVER_NODES="${SERVER_NODES:-}"
NCLI="${NCLI:-5}"                      # liczba wezlow klienckich = liczba pozycji ukladu
if [ -n "$CLIENT_NODES" ]; then NCLI=$(wc -w <<<"$CLIENT_NODES" | awk '{print $1}'); fi
export NUM_CLIENT_NODES="$NCLI"
LAYOUT_MAX="${LAYOUT_MAX:-6}"          # uklady 1..6 workerow na wezel
# RAM_LOG=1: wariant KONTROLNY "log w pamieci" (szczegoly: run_matrix.sh, sekcja RAM_LOG).
# Tu tylko: domyslny PAYLOAD_LIST bez 1MB, straznik na 1MB, sufiks "_ram" w RUN_ID (nizej)
# i wlasna pamiec RUN_ID. Model kosztu (skalibrowany na dysku) ZAWYZA czas punktow bez
# fsync - to bezpieczne: dluzszy BENCH_TIMEOUT i ostrozniejsze kawalki, nic wiecej.
RAM_LOG="${RAM_LOG:-0}"; export RAM_LOG
if [ "$RAM_LOG" = 1 ]; then
  PAYLOAD_LIST="${PAYLOAD_LIST:-1B 1kB}"
  if [ "${RAM_LOG_ALLOW_1MB:-0}" != 1 ]; then
    case " $PAYLOAD_LIST " in *" 1MB "*)
      echo "!! RAM_LOG=1 z ladunkiem 1MB: kilka GB logu na punkt nie zmiesci sie na tmpfs (RAM wezla)."
      echo "   Zostaw domyslne PAYLOAD_LIST=\"1B 1kB\" albo swiadomie RAM_LOG_ALLOW_1MB=1."
      exit 1;;
    esac
  fi
else
  PAYLOAD_LIST="${PAYLOAD_LIST:-1B 1kB 1MB}"
fi
CONN_LIST="${CONN_LIST:-B A}"          # B (polaczenie reuzywane) tanszy -> idzie pierwszy
TRANSPORT_LIST="${TRANSPORT_LIST:-quic tcp}"
# QUIC_SINGLE_STREAM=1: wariant QUIC z JEDNYM strumieniem na polaczenie serwer-serwer
# (run_matrix.sh dodaje serwerom --single-stream; blok TCP bez zmian). Wariant ma WLASNA
# pamiec RUN_ID (~/.matrix6-run-1s) i sufiks "_1s" w domyslnym RUN_ID, zeby jego kawalki
# nie dopisywaly sie do przebiegu zwyklego QUIC ani odwrotnie - w CSV etykieta transportu
# to nadal "QUIC", wariant poznaje sie po run_id i naglowku wyniki.csv. Sens ma tylko
# TRANSPORT_LIST=quic (36 punktow): TCP w takim przebiegu bylby zwyklym, powtorzonym TCP.
QUIC_SINGLE_STREAM="${QUIC_SINGLE_STREAM:-0}"; export QUIC_SINGLE_STREAM
# HB_THREAD=1: heartbeaty z osobnego watku w OBU transportach (run_matrix.sh dodaje serwerom
# --hb-thread; HB-THREAD-CHANGES.md). Wlasna pamiec RUN_ID (~/.matrix6-run_hb) i sufiks "_hb".
# FGAP_MS=<ms> przechodzi do run_matrix.sh (log odstepow miedzy komunikatami u followera).
HB_THREAD="${HB_THREAD:-0}"; export HB_THREAD
[ -n "${FGAP_MS:-}" ] && export FGAP_MS
# RPC_TIMEOUT=MIN,MAX / NO_PREVOTE=1: os limitu elekcji (run_matrix.sh dodaje serwerom
# --rpc-timeout=MIN,MAX / --no-prevote; oba transporty). Sufiksy RUN_ID: _t<MIN> i _np.
RPC_TIMEOUT="${RPC_TIMEOUT:-}"; [ -n "$RPC_TIMEOUT" ] && export RPC_TIMEOUT
NO_PREVOTE="${NO_PREVOTE:-0}"; export NO_PREVOTE
RUN_SUFFIX=""; [ "$QUIC_SINGLE_STREAM" = 1 ] && RUN_SUFFIX="_1s"
[ "$RAM_LOG" = 1 ] && RUN_SUFFIX="${RUN_SUFFIX}_ram"     # wlasna pamiec RUN_ID: ~/.matrix6-run_ram
[ "$HB_THREAD" = 1 ] && RUN_SUFFIX="${RUN_SUFFIX}_hb"     # wlasna pamiec RUN_ID: ~/.matrix6-run_hb
[ -n "$RPC_TIMEOUT" ] && RUN_SUFFIX="${RUN_SUFFIX}_t${RPC_TIMEOUT%%,*}"   # np. _t100 dla 100,200
[ "$NO_PREVOTE" = 1 ] && RUN_SUFFIX="${RUN_SUFFIX}_np"
REQUESTS_DEFAULT="${REQUESTS:-1000}"
REQ_1MB="${REQ_1MB:-$REQUESTS_DEFAULT}"   # osobno, bo to 1MB wysadza budzet
BUDGET_MIN="${BUDGET_MIN:-22}"         # ile minut POMIARU moze miescic jeden kawalek

export SIZES="${SIZES:-5}"
export WARMUP="${WARMUP:-20}"
export REPEATS="${REPEATS:-1}"
export JAVA="${JAVA:-$HOME/jdk21/bin/java -Dlog4j.configuration=file:$HOME/log4j.properties}"
export NAGLOWEK_KEEP=1                 # naglowek opisowy wyniki.csv pisze tylko 1. kawalek
export WYNIKI_CSV="${WYNIKI_CSV:-wyniki.csv}"   # nazwa scalonego pliku (np. wyniki2.csv)
export SERVER_NODES CLIENT_NODES

# ---------------- MODEL KOSZTU ----------------
# latencja bazowa [s] jednej iteracji (zapis+odczyt) i sufit przepustowosci [zadan/s].
# SKALIBROWANE na pelnej macierzy DCC 2026-08-28 (72 punkty): przy 1B/1kB cala iteracja
# to 30-65 ms (takze w conn A - handshake jest tanszy niz zakladane wczesniej 180 ms),
# a od ~15 klientow rzadzi sufit konsensusu ~400 zapisow/s. Przy 1MB rzadzi pasmo lidera:
# ~12.5 zapisow/s niezaleznie od conn (model trafia czas grupy 1MB z bledem <10%).
LAT_1B_B="${LAT_1B_B:-0.040}";  LAT_1B_A="${LAT_1B_A:-0.030}"
LAT_1kB_B="${LAT_1kB_B:-0.040}"; LAT_1kB_A="${LAT_1kB_A:-0.030}"
LAT_1MB_B="${LAT_1MB_B:-0.400}"; LAT_1MB_A="${LAT_1MB_A:-0.400}"
TPUT_SMALL="${TPUT_SMALL:-400}"        # 1B/1kB: sufit konsensusu (zmierzony: 350-470)
TPUT_1MB="${TPUT_1MB:-12.5}"           # 1MB: sufit pasma lidera (zmierzony na DCC)

lat_of() { case "$1_$2" in 1B_B) echo "$LAT_1B_B";; 1B_A) echo "$LAT_1B_A";;
  1kB_B) echo "$LAT_1kB_B";; 1kB_A) echo "$LAT_1kB_A";;
  1MB_B) echo "$LAT_1MB_B";; 1MB_A) echo "$LAT_1MB_A";; *) echo 0.05;; esac; }
tput_of() { [ "$1" = 1MB ] && echo "$TPUT_1MB" || echo "$TPUT_SMALL"; }
req_of()  { [ "$1" = 1MB ] && echo "$REQ_1MB"  || echo "$REQUESTS_DEFAULT"; }

point_s() {   # $1=payload $2=conn $3=workerow -> sekundy (zaokraglone)
  awk -v lat="$(lat_of "$1" "$2")" -v tp="$(tput_of "$1")" -v w="$3" -v r="$(req_of "$1")" \
    'BEGIN{ s = w/tp; if (lat > s) s = lat; printf "%d\n", r*s + 0.5 }'
}
layout_str() { local k="$1" i out=""; for ((i=0;i<NCLI;i++)); do out+="${out:+ }$k"; done; echo "$out"; }
BLOCK_S="${BLOCK_S:-70}"   # start + gotowosc klastra na jeden blok serwerowy

# ---------------- BUDOWA KAWALKOW ----------------
# Kawalek = (payload, conn, PODZBIOR ukladow, OBA transporty). Oba transporty celowo
# w tym samym kawalku: QUIC i TCP dla tej samej konfiguracji maja lezec w JEDNEJ
# rezerwacji, inaczej porownujesz je w innych warunkach klastra. Cena: przy 1MB
# kawalek moze przekroczyc 30 min i wymaga dluzszej rezerwacji - skrypt to wypisze.
NTR=$(wc -w <<<"$TRANSPORT_LIST" | awk '{print $1}')
CH_PL=(); CH_CONN=(); CH_LAY=(); CH_SEC=(); CH_PTS=()

build_chunks() {
  local pl conn k w cost cur_lay cur_cost cur_pts budget=$((BUDGET_MIN * 60))
  for pl in $PAYLOAD_LIST; do
    for conn in $CONN_LIST; do
      cur_lay=""; cur_cost=0; cur_pts=0
      for ((k=1; k<=LAYOUT_MAX; k++)); do
        w=$((k * NCLI))
        cost=$(( $(point_s "$pl" "$conn" "$w") * NTR * REPEATS ))   # oba transporty x powtorzenia
        # nowy kawalek, gdy biezacy juz cos ma i przekroczylby budzet
        if [ -n "$cur_lay" ] && [ $((cur_cost + cost)) -gt "$budget" ]; then
          CH_PL+=("$pl"); CH_CONN+=("$conn"); CH_LAY+=("$cur_lay")
          CH_SEC+=($((cur_cost + BLOCK_S * NTR))); CH_PTS+=("$cur_pts")
          cur_lay=""; cur_cost=0; cur_pts=0
        fi
        cur_lay+="${cur_lay:+ }\"$(layout_str "$k")\""
        cur_cost=$((cur_cost + cost)); cur_pts=$((cur_pts + NTR * REPEATS))
      done
      if [ -n "$cur_lay" ]; then
        CH_PL+=("$pl"); CH_CONN+=("$conn"); CH_LAY+=("$cur_lay")
        CH_SEC+=($((cur_cost + BLOCK_S * NTR))); CH_PTS+=("$cur_pts")
      fi
    done
  done
}
build_chunks
CHUNKS=${#CH_PL[@]}

# Zalecane -t dla salloc: czas kawalka + 8 min zapasu, zaokraglone w gore do 15 min, min 30.
salloc_t() {
  awk -v s="$1" 'BEGIN{ m = int((s + 480 + 899) / 900) * 15; if (m < 30) m = 30;
    printf "%02d:%02d:00\n", int(m/60), m%60 }'
}
lay_pretty() { sed 's/" "/, /g; s/"//g' <<<"$1"; }
lay_count()  { grep -o '"' <<<"$1" | wc -l | awk '{print $1/2}'; }

# ---------------- RUN_ID: katalog i plik wynikow calego przebiegu ----------------
# Tryb kawalkowy MUSI dziedziczyc RUN_ID miedzy rezerwacjami (14 kawalkow -> jeden CSV),
# dlatego jest zapamietywany w ~/.matrix6-run.
# Tryb "all" jest jednorazowy i NIE dziedziczy: drugi pelny przebieg z tym samym RUN_ID
# nadpisalby wiersze pierwszego co do jednego (klucz w scal.sh to run_id + uklad + rep +
# transport + N + payload + conn, a te sa identyczne). Kazde "all" dostaje wiec swoj
# katalog; zeby SWIADOMIE dopisac do starego przebiegu, podaj RUN_ID=... jawnie.
RUN_ID_FROM_ENV="${RUN_ID:-}"
RUN_FILE="$HOME/.matrix6-run${RUN_SUFFIX}"     # warianty (_1s, _ram): osobne pliki
if [ -z "${RUN_ID:-}" ] && [ -f "$RUN_FILE" ]; then RUN_ID="$(cat "$RUN_FILE")"; fi
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)$RUN_SUFFIX}"
export RUN_ID

# Offsety seq/block: kazdy kawalek numeruje punkty tam, gdzie skonczyl poprzedni,
# wiec kolumna seq w wyniki.csv daje ciagla chronologie CALEJ macierzy.
offsets_before() {   # $1 = numer kawalka -> "SEQ0 BLOCK0"
  local i s=0 b=0
  for ((i=0; i<$1-1; i++)); do s=$((s + CH_PTS[i])); b=$((b + NTR)); done
  echo "$s $b"
}

show_plan() {
  local i tot=0 over=0 t pts=0
  echo "=================================================================================="
  echo " MACIERZ: uklady 1..$LAYOUT_MAX workerow/wezel x conn $CONN_LIST x payload $PAYLOAD_LIST"
  echo " N=$SIZES serwerow | zadan/klienta: $REQUESTS_DEFAULT (1MB: $REQ_1MB) | warmup=$WARMUP | repeats=$REPEATS"
  echo " serwery: ${SERVER_NODES:-(z rezerwacji: pierwsze $SIZES wezlow)}"
  echo " klienci: ${CLIENT_NODES:-(z rezerwacji: ostatnie $NCLI wezlow)}  ($NCLI wezlow => uklad $LAYOUT_MAX = $((LAYOUT_MAX*NCLI)) workerow)"
  echo " RUN_ID (wspolny): $RUN_ID"
  if [ "$QUIC_SINGLE_STREAM" = 1 ]; then
    echo " WARIANT: QUIC z jednym strumieniem na polaczenie serwer-serwer (--single-stream)"
    case " $TRANSPORT_LIST " in
      *" tcp "*) echo "   uwaga: TCP na liscie to zwykly TCP (wariant dotyczy tylko QUIC) - zwykle TRANSPORT_LIST=quic";;
    esac
  fi
  [ "$HB_THREAD" = 1 ] && echo " WARIANT: heartbeaty z osobnego watku (--hb-thread), oba transporty${FGAP_MS:+, FGAP_MS=$FGAP_MS}"
  [ -n "$RPC_TIMEOUT" ] && echo " WARIANT: limit elekcji $RPC_TIMEOUT ms, heartbeat co $(( ${RPC_TIMEOUT%%,*} / 2 )) ms (--rpc-timeout), oba transporty"
  [ "$NO_PREVOTE" = 1 ] && echo " WARIANT: pre-vote WYLACZONE (--no-prevote) - kazda proba elekcji obala lidera"
  if [ "$RAM_LOG" = 1 ]; then
    echo " WARIANT KONTROLNY: log w pamieci (storage serwerow na tmpfs ${STORAGE_ROOT:-/dev/shm}, bez trwalosci; oba transporty)"
    echo "   run_matrix.sh sprawdzi tmpfs i wolne miejsce (>= ${RAM_LOG_MIN_MB:-1024} MB) na wezlach serwerowych przed startem"
    echo "   czasy ponizej sa z modelu skalibrowanego NA DYSKU - bez fsync punkty beda krotsze"
  fi
  echo "=================================================================================="
  for ((i=0; i<CHUNKS; i++)); do
    tot=$((tot + CH_SEC[i])); pts=$((pts + CH_PTS[i])); t=$(salloc_t "${CH_SEC[i]}")
    [ "${CH_SEC[i]}" -gt $((30*60)) ] && over=1
    printf ' kawalek %-2d  %-4s conn %s  %2d pkt  ~%3d min   salloc -t %s%s\n' \
      $((i+1)) "${CH_PL[i]}" "${CH_CONN[i]}" "${CH_PTS[i]}" "$(( (CH_SEC[i]+59)/60 ))" "$t" \
      "$([ "${CH_SEC[i]}" -gt $((30*60)) ] && echo '   <-- NIE MIESCI SIE W 30 MIN')"
    printf '             uklady: %s\n' "$(lay_pretty "${CH_LAY[i]}")"
  done
  echo "----------------------------------------------------------------------------------"
  printf ' RAZEM: %d punktow w %d kawalkach, ~%d min (~%s h) czystego pomiaru\n' \
    "$pts" "$CHUNKS" "$(( (tot+59)/60 ))" "$(awk -v s=$tot 'BEGIN{printf "%.1f", s/3600}')"
  echo "=================================================================================="
  if [ "$over" = 1 ]; then
    echo
    echo " UWAGA: kawalki oznaczone powyzej wymagaja rezerwacji DLUZSZEJ niz 30 min."
    echo " Przy 1MB koszt rosnie liniowo z liczba workerow (sufit pasma lidera ~${TPUT_1MB} zapisow/s):"
    echo "   uklad 6 = $((6*NCLI)) workerow x $REQ_1MB zadan po 1MB = $(( 6*NCLI*REQ_1MB/1024 )) GB przez konsensus."
    echo " Dwa wyjscia:"
    echo "   (a) dluzsza rezerwacja dla tych kawalkow:  salloc --no-shell -p dcc -N $((5+NCLI)) -t <wg tabeli>"
    echo "   (b) mniej zadan przy 1MB (ZALECANE - 200 zadan to nadal 1200+ probek w puli):"
    echo "         REQ_1MB=200 bash ~/matrix6.sh plan"
  fi
  echo
  echo " Kolejno, kazdy kawalek w swojej rezerwacji:"
  echo "   salloc --no-shell -p dcc -N $((5+NCLI)) -t 00:30:00   # -t wg tabeli wyzej"
  echo "   bash ~/matrix6.sh 1"
  echo "   scancel <jobid>"
}

RM="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run_matrix.sh"

# ---------------- TRYB "all": CALA MACIERZ JEDNA KOMENDA ----------------
# Dla dlugiej rezerwacji (kilka godzin) ciecie na kawalki nie ma sensu. Grupujemy wtedy
# TYLKO po payloadzie - bo tylko on zmienia liczbe zadan (REQ_1MB) - i kazda grupa to
# JEDNO wywolanie run_matrix.sh z wszystkimi ukladami, oboma conn i oboma transportami.
# Efekt: 3 grupy x 2 transporty = 6 restartow serwerow na cale 72 punkty (kawalki
# potrzebowalyby 28). seq i block lecza sie miedzy grupami przez SEQ0/BLOCK0.
run_all() {
  local pl grp=0 seq0=0 blk0=0 pts est tot=0
  local nlay="$LAYOUT_MAX" nconn ntr="$NTR"
  nconn=$(wc -w <<<"$CONN_LIST" | awk '{print $1}')
  pts=$((nlay * nconn * ntr * REPEATS))

  # Swiezy katalog na kazdy pelny przebieg - patrz komentarz przy RUN_ID wyzej.
  if [ -z "$RUN_ID_FROM_ENV" ]; then
    RUN_ID="$(date +%Y%m%d_%H%M%S)$RUN_SUFFIX"; export RUN_ID
  else
    echo "-- RUN_ID podany jawnie: dopisuje do ISTNIEJACEGO przebiegu $RUN_ID"
    echo "   (punkty o tych samych parametrach zostana NADPISANE nowym pomiarem)"
  fi

  echo "=================================================================================="
  echo " CALA MACIERZ JEDNYM PRZEBIEGIEM"
  echo " $((pts * $(wc -w <<<"$PAYLOAD_LIST" | awk '{print $1}'))) punktow"\
       "| uklady 1..$LAYOUT_MAX | conn $CONN_LIST | payload $PAYLOAD_LIST | $TRANSPORT_LIST" \
       "$([ "$QUIC_SINGLE_STREAM" = 1 ] && echo '| QUIC: JEDEN STRUMIEN')" \
       "$([ "$HB_THREAD" = 1 ] && echo '| HEARTBEAT: OSOBNY WATEK')" \
       "$([ -n "$RPC_TIMEOUT" ] && echo "| LIMIT ELEKCJI $RPC_TIMEOUT ms")" \
       "$([ "$NO_PREVOTE" = 1 ] && echo '| BEZ PRE-VOTE')" \
       "$([ "$RAM_LOG" = 1 ] && echo '| KONTROLA: LOG W PAMIECI (tmpfs, bez trwalosci)')"
  echo " zadan/klienta: $REQUESTS_DEFAULT (1MB: $REQ_1MB) | powtorzen: $REPEATS | plik: $WYNIKI_CSV | RUN_ID=$RUN_ID"
  for pl in $PAYLOAD_LIST; do
    est=0
    for ((k=1; k<=LAYOUT_MAX; k++)); do
      for c in $CONN_LIST; do est=$((est + $(point_s "$pl" "$c" $((k*NCLI))) * ntr * REPEATS)); done
    done
    est=$((est + BLOCK_S * ntr)); tot=$((tot + est))
    printf " grupa %-4s %2d punktow  ~%3d min\n" "$pl" "$pts" "$(( (est+59)/60 ))"
  done
  echo " RAZEM ~$(( (tot+59)/60 )) min (~$(awk -v s=$tot 'BEGIN{printf "%.1f", s/3600}') h)"\
       "- rezerwacja musi byc DLUZSZA"
  echo "=================================================================================="

  # RUN_ID zapamietujemy tylko przy prawdziwym pomiarze (DRYRUN nie zajmuje numeru).
  [ "${DRYRUN:-0}" = 1 ] || echo "$RUN_ID" > "$RUN_FILE"
  for pl in $PAYLOAD_LIST; do
    grp=$((grp + 1))
    export PAYLOADS="$pl" CONNS="$CONN_LIST" TRANSPORTS="$TRANSPORT_LIST"
    export CLIENT_LAYOUTS="$LAYOUTS_ALL_STR"
    export REQUESTS="$(req_of "$pl")"
    export SEQ0="$seq0" BLOCK0="$blk0"
    # najdrozszy punkt grupy (najwiekszy uklad) x2 zapasu - timeout ma zdazyc PRZED SLURM-em
    export EST_POINT_S="$(point_s "$pl" "$(awk '{print $NF}' <<<"$CONN_LIST")" $((LAYOUT_MAX*NCLI)))"
    export BENCH_TIMEOUT="$(( EST_POINT_S * 2 + 300 ))"
    echo
    echo "############ GRUPA $grp/$(wc -w <<<"$PAYLOAD_LIST" | awk '{print $1}'): payload=$pl,"\
         "zadan=$REQUESTS, punkty seq $((seq0+1))..$((seq0+pts)) ############"
    # Padnieta grupa NIE przerywa reszty - wyniki wczesniejszych punktow sa juz w CSV
    # (scal.sh dopisuje wiersz po kazdym punkcie), a kolejny payload moze przejsc bez problemu.
    if ! bash "$RM"; then
      echo "!! GRUPA $grp (payload=$pl) przerwana - przechodze do nastepnej"
      echo "grupa=$grp payload=$pl PRZERWANA" >> "$HOME/raft-results/$RUN_ID/ODRZUCONE.txt" 2>/dev/null || true
    fi
    seq0=$((seq0 + pts)); blk0=$((blk0 + ntr))
  done
  local out="$HOME/raft-results/$RUN_ID/$WYNIKI_CSV" rows=0
  [ -f "$out" ] && rows=$(grep -vc '^#\|^run_id,' "$out" || true)
  echo
  echo "=================================================================================="
  echo " KONIEC: $rows wierszy w $out"
  [ -f "$HOME/raft-results/$RUN_ID/ODRZUCONE.txt" ] \
    && echo " Punkty z zastrzezeniami: $HOME/raft-results/$RUN_ID/ODRZUCONE.txt"
  echo "=================================================================================="
}

# Wszystkie uklady jako jeden lancuch dla CLIENT_LAYOUTS ('"1 1 .." "2 2 .." ...').
LAYOUTS_ALL_STR=""
for ((k=1; k<=LAYOUT_MAX; k++)); do
  LAYOUTS_ALL_STR+="${LAYOUTS_ALL_STR:+ }\"$(layout_str "$k")\""
done

# ---------------- URUCHOMIENIE ----------------
CMD="${1:-plan}"
case "$CMD" in
  plan|--plan|-p) show_plan; exit 0 ;;
  all|--all|-a)
    [ -f "$RM" ] || { echo "!! brak run_matrix.sh obok matrix6.sh ($RM)"; exit 1; }
    run_all; exit 0 ;;
  ''|*[!0-9]*) echo "uzycie: bash matrix6.sh {plan | all | <numer kawalka 1..$CHUNKS>}"; exit 1 ;;
esac
[ "$CMD" -ge 1 ] && [ "$CMD" -le "$CHUNKS" ] \
  || { echo "!! nie ma kawalka $CMD (jest 1..$CHUNKS; 'bash matrix6.sh plan')"; exit 1; }

IDX=$((CMD - 1))
read -r SEQ0 BLOCK0 <<<"$(offsets_before "$CMD")"
export SEQ0 BLOCK0
export PAYLOADS="${CH_PL[$IDX]}" CONNS="${CH_CONN[$IDX]}" CLIENT_LAYOUTS="${CH_LAY[$IDX]}"
export TRANSPORTS="$TRANSPORT_LIST"
export REQUESTS="$(req_of "${CH_PL[$IDX]}")"
export EST_POINT_S=$(( CH_SEC[IDX] / (CH_PTS[IDX] > 0 ? CH_PTS[IDX] : 1) ))
# BENCH_TIMEOUT musi byc KROTSZY od rezerwacji, inaczej SLURM ubije zadanie pierwszy
# i zawieszony przebieg nie zostawi ani komunikatu, ani logow. Bierzemy najdluzszy
# przewidywany punkt tego kawalka x2 zapasu.
export BENCH_TIMEOUT="${BENCH_TIMEOUT:-$(( EST_POINT_S * 2 + 300 ))}"

echo "=== KAWALEK $CMD/$CHUNKS: payload=${CH_PL[$IDX]} conn=${CH_CONN[$IDX]} transporty=$TRANSPORT_LIST$([ "$QUIC_SINGLE_STREAM" = 1 ] && echo ' [QUIC: jeden strumien]')$([ "$RAM_LOG" = 1 ] && echo ' [KONTROLA: log w pamieci]')$([ "$HB_THREAD" = 1 ] && echo ' [heartbeat: osobny watek]')$([ -n "$RPC_TIMEOUT" ] && echo " [limit elekcji $RPC_TIMEOUT]")$([ "$NO_PREVOTE" = 1 ] && echo ' [bez pre-vote]')"
echo "    uklady: $(lay_pretty "${CH_LAY[$IDX]}")"
echo "    zadan/klienta: $REQUESTS | punktow: ${CH_PTS[$IDX]} | szacunek: ~$(( (CH_SEC[IDX]+59)/60 )) min"
echo "    RUN_ID=$RUN_ID -> ~/raft-results/$RUN_ID/$WYNIKI_CSV (seq od $((SEQ0+1)))"
echo "    BENCH_TIMEOUT=${BENCH_TIMEOUT}s"
if [ "${CH_SEC[$IDX]}" -gt $((30*60)) ]; then
  echo "    !! ten kawalek potrzebuje rezerwacji -t $(salloc_t "${CH_SEC[$IDX]}"), nie 30 min"
fi

[ -f "$RM" ] || { echo "!! brak run_matrix.sh obok matrix6.sh ($RM)"; exit 1; }
# RUN_ID zapamietujemy dopiero gdy naprawde mierzymy - 'plan' i DRYRUN nie zajmuja numeru.
[ "${DRYRUN:-0}" = 1 ] || echo "$RUN_ID" > "$RUN_FILE"

bash "$RM"

echo
if [ "$CMD" -lt "$CHUNKS" ]; then
  echo "=== kawalek $CMD gotowy. scancel, nowa rezerwacja, potem:  bash ~/matrix6.sh $((CMD+1))"
else
  echo "=== ostatni kawalek gotowy. Cala macierz: ~/raft-results/$RUN_ID/$WYNIKI_CSV"
fi
