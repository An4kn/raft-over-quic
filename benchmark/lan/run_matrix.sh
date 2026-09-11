#!/usr/bin/env bash
#
# MACIERZ benchmarku Raft-over-QUIC vs TCP+TLS na klastrze DCC (SLURM).
# Kopia run_lan.sh z jedna nowa osia sweepu: UKLADY KLIENTOW (CLIENT_LAYOUTS) - kilka
# rozkladow workerow po wezlach klienckich w JEDNYM wywolaniu. Do tego kolejnosc wykonania
# widoczna w wyniki.csv (kolumny seq/block/layout) i naglowek opisowy w tym pliku.
# UWAGA: poprawki w run_lan.sh trzeba nanosic tez tutaj (i odwrotnie) - swiadomy koszt kopii.
#
# Uruchamiaj NA WEZLE DOSTEPOWYM klastra: bash ~/run_matrix.sh
#
# Wymagania (RUNBOOK §2/§3): jak run_lan.sh (~/jdk21, ~/ratis.jar, ~/netty-quiche-linux.jar,
# ~/ratis-test/.../ssl, ssh bez hasla) + ~/scal.sh (scalanie wyniki.csv) + ~/log4j.properties
# w JAVA= (bez tego kolumna elections bedzie zawsze 0).
#
# TEN SKRYPT TYLKO MIERZY - nigdy nie rezerwuje i nigdy nie zwalnia wezlow (alloc.sh).
#
# Przyklady:
#   # trzy uklady klientow, jeden po drugim, w jednej rezerwacji:
#   SERVER_NODES="dcc-1 dcc-2 dcc-3 dcc-4 dcc-5" \
#   CLIENT_NODES="dcc-9 dcc-10 dcc-11 dcc-12 dcc-13" \
#   CLIENT_LAYOUTS='"1 1 1 1 1" "2 2 2 2 2" "3 3 3 3 3"' \
#   SIZES=5 PAYLOADS=1MB CONNS=A TRANSPORTS="quic tcp" REQUESTS=200 REPEATS=1 \
#     bash ~/run_matrix.sh
#
#   # najpierw zobacz plan bez dotykania klastra (lista punktow w kolejnosci + szacunek czasu):
#   DRYRUN=1 CLIENT_LAYOUTS='"1 1 1 1 1" "3 3 3 3 3"' SIZES=5 PAYLOADS=1MB CONNS=A \
#     TRANSPORTS="quic tcp" REPEATS=1 bash ~/run_matrix.sh
#
#   # wariant kontrolny "log w pamieci" (RAM_LOG=1, storage serwerow na tmpfs; patrz nizej):
#   RAM_LOG=1 PAYLOADS="1B 1kB" CLIENT_LAYOUTS='"1 1 1 1 1"' SIZES=5 bash ~/run_matrix.sh
#
# Kolejnosc petli (celowo): N { transport { payload { conn { LAYOUT { rep } } } } }
#   - transporty to osobne BLOKI serwerowe (restart klastra), w CSV kolumna block=<nr>-<transport>;
#   - uklady leca bezposrednio po sobie w tych samych warunkach - to je sie porownuje;
#   - kolumna seq = numer wykonania punktu; sortowanie po seq = chronologia przebiegu.
#
# Szybkosc startu (skrypt wypisuje [czas] dla kazdego kroku):
#   SSH_MUX=0        wylacza multipleksowanie ssh (gdyby sockety sprawialy klopoty)
#   PROBE_ATTEMPT=30 timeout POJEDYNCZEJ proby gotowosci (RaftBench, sekundy)
#   PROBE_TIMEOUT=120 laczny czas na doczekanie sie gotowego klastra
#   SOCK_TIMEOUT=120 laczny czas na pojawienie sie gniazd :PORT
set -euo pipefail

# ---------------- KONFIGURACJA ----------------
SIZES="${SIZES:-3 5 7}"              # rozmiary klastra do przemiatania (nieparzyste!)
# Etykiety transportow: TYLKO "quic" i "tcp". Pod "tcp" siedzi stos TCP+TLS. Etykieta idzie
# wszedzie: katalogi na wezlach, nazwy logow i CSV, kolumna block w wyniki.csv - zeby w
# wynikach nie mieszala sie nazwa biblioteki z nazwa protokolu. Inna wartosc = blad (nizej).
TRANSPORTS="${TRANSPORTS:-quic tcp}"
CONNS="${CONNS:-A B}"

# --runall: pelne porownanie w ustalonej kolejnosci - najpierw TCP (conn A i B),
# potem QUIC (conn A i B). Nadpisuje TRANSPORTS i CONNS; reszta parametrow
# (SIZES, PAYLOADS, REPEATS, ...) dziala normalnie.
for arg in "$@"; do
  if [ "$arg" = "--runall" ]; then
    TRANSPORTS="tcp quic"
    CONNS="A B"
  fi
done
# Walidacja etykiet PRZED dotknieciem klastra: literowka w TRANSPORTS inaczej wyszlaby
# dopiero przy starcie serwerow, czyli po zjedzeniu minuty rezerwacji.
for _t in $TRANSPORTS; do
  [ "$_t" = quic ] || [ "$_t" = tcp ] \
    || { echo "!! TRANSPORTS: '$_t' - dozwolone sa tylko 'quic' i 'tcp'"; exit 1; }
done
unset _t
# QUIC_SINGLE_STREAM=1: wariant QUIC z JEDNYM strumieniem na polaczenie serwer-serwer
# (serwery dostaja "--quic --single-stream" = raft.quic.server.single-stream=true).
# Wszystkie typy komunikatow (AppendEntries, heartbeat, RequestVote, ...) ida wtedy jednym
# strumieniem, jak jednym polaczeniem TCP. Sluzy do wyodrebnienia wkladu podzialu na
# strumienie: ten sam stos QUIC, inny tylko uklad strumieni. Blok TCP i klienci bez zmian.
# Etykieta transportu w CSV zostaje "QUIC" - wariant odroznia RUN_ID oraz wpis w meta.txt
# i w naglowku wyniki.csv, dlatego NIE dopisuj takiego przebiegu do RUN_ID zwyklego QUIC.
QUIC_SINGLE_STREAM="${QUIC_SINGLE_STREAM:-0}"
# HB_THREAD=1: wariant "heartbeaty z osobnego watku" (HB-THREAD-CHANGES.md). Serwery OBU
# transportow dostaja --hb-thread (= raft.server.log.appender.heartbeat.thread=true): lider
# wysyla heartbeat do followera z osobnego watku, wiec heartbeat leci OBOK paczki
# AppendEntries / fragmentu migawki, zamiast dopiero po ich odpowiedzi. Domyslny appender
# ma jedno zadanie w locie na followera, wiec bez tej opcji osobny strumien heartbeatow
# w QUIC nigdy nie ma czego rozdzielac. Etykiety transportow w CSV bez zmian - wariant
# poznaje sie po run_id (matrix6.sh: sufiks _hb), meta.txt i naglowku wyniki.csv.
# FGAP_MS=<ms>: dodatkowo serwery loguja "FGAP <id> <ms> <typ>" (odstep miedzy kolejnymi
# komunikatami od lidera u followera, gdy >= prog) - -Dratis.fgap.threshold.ms.
HB_THREAD="${HB_THREAD:-0}"
SERVER_JAVA_OPTS="${SERVER_JAVA_OPTS:-}"
[ -n "${FGAP_MS:-}" ] && SERVER_JAVA_OPTS="$SERVER_JAVA_OPTS -Dratis.fgap.threshold.ms=$FGAP_MS"
# RPC_TIMEOUT=MIN,MAX (ms): limit elekcji OBU transportow (raft.server.rpc.timeout.min/max),
# odstep heartbeatow = MIN/2 (tak liczy Ratis). NO_PREVOTE=1: klasyczny Raft bez fazy
# pre-vote. Oba ida do serwerow jako flagi --rpc-timeout=MIN,MAX / --no-prevote; bez nich
# domyslne Ratisa: 150,300 i pre-vote wlaczone. Liczniki z logow serwerow na punkt:
# elections = przejscia "to LEADER" lub "ELECTION round N: result PASSED", candidate_attempts =
# przejscia "FOLLOWER to CANDIDATE" lub "PRE_VOTE/ELECTION round 0: submit vote requests" - liczone
# z obu loggerow (RaftServerImpl, LeaderElection), brane maksimum; wymaga ~/log4j.properties z INFO
# dla co najmniej jednego z nich (z pre-vote to proby, ktore zwykle przepadaja; bez pre-vote kazda
# proba obala lidera).
RPC_TIMEOUT="${RPC_TIMEOUT:-}"
NO_PREVOTE="${NO_PREVOTE:-0}"
# READTPUT=1: po punktach kazdego bloku, na ZYWYM klastrze, dodatkowy pomiar "sama
# przepustowosc danych": sami czytelnicy (RaftBench --mode scaling --read-ratio 1.0), stale
# read (minIndex=0) z followerow, odpowiedz = ladunek READTPUT_PAYLOAD (domyslnie 1MB) prosto
# z pamieci followera. Zero konsensusu, zero dysku, zero tmpfs - tylko stos transportowy
# i obsluga zadania na serwerze. Po jednym procesie na wezel kliencki, READTPUT_CLIENTS
# czytelnikow w procesie (OD:DO:KROK RaftBench, domyslnie 6:6:1 = 30 czytelnikow lacznie),
# READTPUT_REQ odczytow na czytelnika. Wynik scalony (suma przepustowosci, srednia p50,
# max p99) w $RESULTS/readtput.csv, surowe CSV procesow w readtput_<tr>_n<N>_<wezel>.csv.
READTPUT="${READTPUT:-0}"
READTPUT_CLIENTS="${READTPUT_CLIENTS:-6:6:1}"
READTPUT_PAYLOAD="${READTPUT_PAYLOAD:-1MB}"
READTPUT_REQ="${READTPUT_REQ:-200}"
READTPUT_FROM="${READTPUT_FROM:-followers}"
# rywrites: kazdy worker pisze do lidera i czyta SWOJ klucz z przypisanego followera.
# --read-ratio / --read-from NIE dzialaja w tym trybie - nie podawac.
#
# Klienci - dwa tryby:
#   (a) bez CLIENT_LAYOUTS/CLIENT_SPLIT: JEDEN proces RaftBench na pierwszym wezle
#       klienckim, z BENCH_CLIENTS jako OD:DO:KROK (tak jak dotad);
#   (b) CLIENT_LAYOUTS='"1 1 1 1 1" "2 2 2 2 2"': NOWA OS SWEEPU - lista ukladow;
#       kazdy uklad to po jednym procesie na KAZDYM wezle klienckim, pozycja i mowi,
#       ilu workerow dostaje CLIENT_NODES[i]. Kazdy proces dostaje --worker-offset
#       (narastajaco), wiec id workerow sa globalnie unikalne - id to klucz w state
#       machine i bez offsetu procesy nadpisywalyby sobie dane. Follower przypisywany
#       jest z globalnego id, wiec rozklad po followerach wychodzi taki sam, jakby
#       wszyscy siedzieli w jednym procesie. CLIENT_SPLIT="8 8 8 6" dziala jak dotad
#       (= CLIENT_LAYOUTS z jednym ukladem).
BENCH_CLIENTS="${BENCH_CLIENTS:-8:8:1}"   # tylko tryb (a); <=10 workerow na proces JVM
CLIENT_SPLIT="${CLIENT_SPLIT:-}"          # tryb (b), jeden uklad (alias)
CLIENT_LAYOUTS="${CLIENT_LAYOUTS:-}"      # tryb (b), wiele ukladow: '"1 1 1" "2 2 2"'
PAYLOADS="${PAYLOADS:-1kB}"          # lista, np. "64 1kB 1MB" - przemiatana jak SIZES
REQUESTS="${REQUESTS:-500}"
WARMUP="${WARMUP:-20}"
REPEATS="${REPEATS:-3}"              # 3 przebiegi; pierwszy odrzucic (zimna JVM), mediana z reszty
BENCH_TIMEOUT="${BENCH_TIMEOUT:-900}"   # tryb (b): ile sekund czekac na procesy klienckie
DRYRUN="${DRYRUN:-0}"                # 1 = wypisz plan punktow i szacunek czasu, nic nie rob

# RAM_LOG=1: wariant KONTROLNY "log w pamieci". Katalog roboczy serwerow (czyli storage
# Ratisa: log, metadane, snapshoty) lezy na tmpfs (/dev/shm) zamiast na dysku w /data.
# fsync na tmpfs konczy sie natychmiast, wiec z rundy AppendEntries i z zatwierdzenia znika
# zapis trwaly - zostaje siec, stos transportowy i obsluga w serwerze. Oba transporty tak
# samo; obciazenie (rywrites, uklady, liczba zadan) IDENTYCZNE z macierza glowna, rozni sie
# tylko nosnik logu - dlatego wolno porownywac punkt w punkt z przebiegiem na dysku.
# To NIE jest konfiguracja produkcyjna Rafta (brak trwalosci) - tylko kontrola.
# Etykiety transportow w CSV bez zmian; wariant odroznia RUN_ID (matrix6.sh dokleja "_ram"),
# wpis ram_log=1 w meta.txt i linia "# WARIANT KONTROLNY" w naglowku wyniki.csv.
# STORAGE_ROOT mozna podac wprost (inny tmpfs); bez RAM_LOG zostaje /data jak dotad.
# Przed startem serwerow check_ram_log sprawdza na kazdym wezle serwerowym, ze STORAGE_ROOT
# jest tmpfs i ma >= RAM_LOG_MIN_MB wolnego (domyslnie 1024 MB) - inaczej konczy sie bledem,
# zanim cokolwiek ruszy. Po kazdym bloku storage na tmpfs jest kasowany (to RAM wezla).
# Ladunek 1MB do tego wariantu sie NIE nadaje (GB logu na punkt) - straznik ponizej.
RAM_LOG="${RAM_LOG:-0}"
if [ "$RAM_LOG" = 1 ]; then
  STORAGE_ROOT="${STORAGE_ROOT:-/dev/shm}"
else
  STORAGE_ROOT="${STORAGE_ROOT:-/data}"
fi
RAM_LOG_MIN_MB="${RAM_LOG_MIN_MB:-1024}"
if [ "$RAM_LOG" = 1 ] && [ "${RAM_LOG_ALLOW_1MB:-0}" != 1 ]; then
  case " $PAYLOADS " in *" 1MB "*)
    echo "!! RAM_LOG=1 z ladunkiem 1MB: kilka GB logu na punkt nie zmiesci sie na tmpfs (RAM wezla)."
    echo "   Uzyj PAYLOADS=\"1B 1kB\" (w matrix6.sh: PAYLOAD_LIST) albo swiadomie RAM_LOG_ALLOW_1MB=1."
    exit 1;;
  esac
fi

# ---- CLIENT_LAYOUTS -> tablica LAYOUTS (bez eval; straznik: tylko cyfry/spacje/cudzyslowy) ----
LAYOUTS=()
if [ -n "$CLIENT_LAYOUTS" ]; then
  [[ "$CLIENT_LAYOUTS" =~ ^[0-9\ \"]+$ ]] \
    || { echo "!! CLIENT_LAYOUTS: dozwolone tylko cyfry, spacje i cudzyslowy: $CLIENT_LAYOUTS"; exit 1; }
  if [[ "$CLIENT_LAYOUTS" == *'"'* ]]; then
    _s="$CLIENT_LAYOUTS"
    while [[ "$_s" =~ \"([0-9][0-9\ ]*)\" ]]; do
      LAYOUTS+=("${BASH_REMATCH[1]}")
      _s="${_s#*\"${BASH_REMATCH[1]}\"}"
    done
    unset _s
  else
    LAYOUTS=("$CLIENT_LAYOUTS")    # bez cudzyslowow = jeden uklad
  fi
  [ "${#LAYOUTS[@]}" -gt 0 ] || { echo "!! CLIENT_LAYOUTS: nie znalazlem zadnego ukladu w: $CLIENT_LAYOUTS"; exit 1; }
elif [ -n "$CLIENT_SPLIT" ]; then
  LAYOUTS=("$CLIENT_SPLIT")        # stare wywolania dzialaja bez zmian
fi
# Walidacja TERAZ, przed dotknieciem klastra - blad tutaj kosztowalby rezerwacje:
# kazda pozycja to liczba > 0, wszystkie uklady maja TE SAMA liczbe pozycji.
LAYOUT_LEN=0
for lay in ${LAYOUTS[@]+"${LAYOUTS[@]}"}; do
  read -ra _l <<<"$lay"
  for x in "${_l[@]}"; do
    [[ "$x" =~ ^[1-9][0-9]*$ ]] || { echo "!! uklad '$lay': '$x' nie jest liczba > 0"; exit 1; }
  done
  if [ "$LAYOUT_LEN" -eq 0 ]; then LAYOUT_LEN="${#_l[@]}"
  elif [ "${#_l[@]}" -ne "$LAYOUT_LEN" ]; then
    echo "!! uklady maja rozne liczby pozycji: '$lay' ma ${#_l[@]}, wczesniejsze $LAYOUT_LEN"
    echo "   (kazda pozycja = jeden wezel kliencki, wiec liczba pozycji musi byc stala)"
    exit 1
  fi
done
unset _l lay x

PORT="${PORT:-10024}"
# Ktore wezly sa serwerami, a ktore klientami:
#   SERVER_NODES="dcc-1 dcc-2 dcc-3 dcc-4 dcc-5"  - pula serwerow; dla N bierze sie pierwsze N
#   CLIENT_NODES="dcc-9 dcc-10 dcc-11 dcc-12"     - wezly klienckie, w tej kolejnosci
# Obie listy musza zawierac sie w rezerwacji. Bez nich obowiazuje regula POZYCYJNA:
# klienci = OSTATNIE NUM_CLIENT_NODES wezlow alokacji, serwery = reszta w kolejnosci alokacji.
SERVER_NODES="${SERVER_NODES:-}"
CLIENT_NODES="${CLIENT_NODES:-}"
read -ra SERVER_NODES_ARR <<<"$SERVER_NODES"
read -ra CLIENT_NODES_ARR <<<"$CLIENT_NODES"

# NUM_CLIENT_NODES wynika z list, jesli sa; podany jawnie musi sie z nimi zgadzac.
NUM_CLIENT_NODES_GIVEN="${NUM_CLIENT_NODES:-}"
if [ "${#CLIENT_NODES_ARR[@]}" -gt 0 ]; then
  NUM_CLIENT_NODES="${#CLIENT_NODES_ARR[@]}"
elif [ "$LAYOUT_LEN" -gt 0 ]; then
  NUM_CLIENT_NODES="$LAYOUT_LEN"
else
  NUM_CLIENT_NODES="${NUM_CLIENT_NODES:-1}"   # ile OSTATNICH wezlow alokacji to klienci
fi
if [ -n "$NUM_CLIENT_NODES_GIVEN" ] && [ "$NUM_CLIENT_NODES_GIVEN" != "$NUM_CLIENT_NODES" ]; then
  echo "!! NUM_CLIENT_NODES=$NUM_CLIENT_NODES_GIVEN, a CLIENT_NODES/uklady maja $NUM_CLIENT_NODES pozycji"
  exit 1
fi
if [ "$LAYOUT_LEN" -gt 0 ] && [ "$LAYOUT_LEN" -ne "$NUM_CLIENT_NODES" ]; then
  echo "!! uklady maja $LAYOUT_LEN pozycji, a wezlow klienckich jest $NUM_CLIENT_NODES"
  exit 1
fi

# Znacznik ukladu do nazw plikow i kolumny w CSV: spacje -> myslniki ("1 1 1" -> "1-1-1");
# spacja w CSV wymagalaby cudzyslowow i psula proste awk/cut. Tryb (a) dostaje "-".
layout_tag() { local l="${1:-}"; [ -n "$l" ] && echo "${l// /-}" || echo "-"; }
layout_total() { local s=0 k; for k in $1; do s=$((s + k)); done; echo "$s"; }
# Skad wziac rezerwacje: jawne JOBID= wygrywa, inaczej czytamy plik od alloc.sh.
# Wezlow NIE zwalniamy w zadnym przypadku - robi to `bash alloc.sh free`.
JOBID="${JOBID:-}"
ALLOC_FILE="${ALLOC_FILE:-$HOME/.raft-alloc}"

# JAVA mozna nadpisac, zeby dolozyc flagi JVM bez dotykania skryptu, np.
#   JAVA="$HOME/jdk21/bin/java -Dlog4j.configuration=file:$HOME/log4j.properties"
#   JAVA="$HOME/jdk21/bin/java -Xmx4g"
JAVA="${JAVA:-$HOME/jdk21/bin/java}"
# JVM KLIENTOW osobno: wezly klienckie maja 4GB RAM i przy 1MB payload JVM potrafi
# zostac zabita przez OOM (znikajace wezly, finished=4/5). Limit pamieci wolno nalozyc
# TYLKO na klientow - serwery (8GB) sa systemem pod pomiarem i ich JVM nie ruszamy.
#   CLIENT_JAVA="$HOME/jdk21/bin/java -Dlog4j.configuration=file:$HOME/log4j.properties -Xmx1g -XX:MaxDirectMemorySize=768m"
CLIENT_JAVA="${CLIENT_JAVA:-$JAVA}"
JAR="$HOME/ratis.jar"
CP="$JAR:$HOME/netty-quiche-linux.jar"
SERVER_CLASS=org.apache.ratis.examples.counter.server.CounterServer
BENCH_CLASS=org.apache.ratis.examples.counter.client.RaftBench
# CounterClient nie jest juz uzywany - probe gotowosci robi RaftBench (patrz wait_ready).

# RUN_ID mozna narzucic z zewnatrz: matrix6.sh daje wszystkim swoim kawalkom WSPOLNY
# RUN_ID, wiec wiele rezerwacji dopisuje do jednego katalogu i jednego wyniki.csv
# (klucz w scal.sh nadpisuje powtorzone punkty zamiast je dublowac).
RUN_ID="${RUN_ID:-$(date +%Y%m%d_%H%M%S)}"
RESULTS="$HOME/raft-results/$RUN_ID"     # NFS home - przezywa uspienie wezlow
# Offsety licznikow kolejnosci dla przebiegow cietych na kawalki (matrix6.sh): kazdy
# kawalek zaczyna seq/block od swojego miejsca w CALOSCI, wiec chronologia w CSV sie sklada.
SEQ0="${SEQ0:-0}"
BLOCK0="${BLOCK0:-0}"
BOOT_TIMEOUT="${BOOT_TIMEOUT:-300}"      # wybudzenie wezla trwa ~3 min

MAX_N=0; for n in $SIZES; do [ "$n" -gt "$MAX_N" ] && MAX_N=$n; done
TOTAL_NODES=$((MAX_N + NUM_CLIENT_NODES))
# NODES = cala rezerwacja; SERVER_POOL = kandydaci na serwery (dla N bierze sie pierwsze N);
# SERVERS = serwery biezacego N; CLIENTS = wezly klienckie.
NODES=(); SERVER_POOL=(); SERVERS=(); CLIENTS=()

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }

# ---------------- 0. SSH: jedno polaczenie na wezel + petle rownolegle ----------------
# Kazde nowe ssh do wezla to pelny handshake (~0.3-0.8 s). Faza startowa robila ich
# kilkadziesiat sekwencyjnie (preclean, pkill, mkdir, start, ss, pgrep) i to - a nie JVM -
# zjadalo wieksza czesc minuty. ControlMaster trzyma JEDNO polaczenie na wezel, kolejne
# wywolania wchodza przez ten sam socket (~20 ms). SSH_MUX=0 wylacza, gdyby socket
# sprawial klopoty (np. inny przebieg trzyma stary socket po zmianie wezlow).
SSH_MUX="${SSH_MUX:-1}"
SSH_CM_DIR="${SSH_CM_DIR:-/tmp/raft-ssh-$USER}"
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
if [ "$SSH_MUX" = 1 ]; then
  mkdir -p "$SSH_CM_DIR" && chmod 700 "$SSH_CM_DIR"
  # ControlPath per wezel (%h): dwa rozne wezly nigdy nie scigaja sie o ten sam socket,
  # a rownolegle wywolania do TEGO SAMEGO wezla i tak sa w skrypcie pojedyncze.
  SSH_OPTS+=(-o ControlMaster=auto -o "ControlPath=$SSH_CM_DIR/%h" -o ControlPersist=600)
fi
sshx()  { ssh -n "${SSH_OPTS[@]}" "$@"; }   # zwykle, blokujace
sshbg() { ssh -f "${SSH_OPTS[@]}" "$@"; }   # odpalenie procesu w tle na wezle

# To samo polecenie na wielu wezlach NARAZ. Petla sekwencyjna kosztuje sume czasow ssh,
# tu placimy tylko za najwolniejszy wezel. Podpowloki '&' NIE dziedzicza trapa EXIT,
# wiec zakonczenie takiego zadania nie odpala cleanup.
pssh() {   # $1=polecenie, $2..=wezly
  local cmd="$1"; shift
  local n p rc=0
  local -a pids=()
  for n in "$@"; do sshx "$n" "$cmd" >/dev/null 2>&1 & pids+=($!); done
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || rc=1; done
  return "$rc"
}

# Ile wezlow z listy spelnia warunek (polecenie konczy sie zerem) - tez rownolegle.
pcount() {   # $1=polecenie, $2..=wezly ; echo -> liczba
  local cmd="$1"; shift
  local n p ok=0
  local -a pids=()
  for n in "$@"; do sshx "$n" "$cmd" >/dev/null 2>&1 & pids+=($!); done
  for p in ${pids[@]+"${pids[@]}"}; do if wait "$p"; then ok=$((ok+1)); fi; done
  echo "$ok"
}

# Pomiar krokow startowych - zeby bylo widac, gdzie faktycznie idzie czas.
TIC=0
tic() { TIC=$SECONDS; }
toc() { log "  [czas] $1: $((SECONDS - TIC))s"; }

# ---------------- 1. UZYCIE ISTNIEJACEJ REZERWACJI ----------------
# Ten skrypt NIE rezerwuje. Bierze wezly z rezerwacji zrobionej przez alloc.sh
# (albo ze wskazanego JOBID=) i nigdy jej nie zwalnia.
use_allocation() {
  mkdir -p "$RESULTS"
  # 1) jawne JOBID= wygrywa
  # 2) plik od alloc.sh
  # 3) wlasna dzialajaca rezerwacja (np. zrobiona recznie przez salloc) - jesli jest DOKLADNIE jedna
  if [ -z "$JOBID" ] && [ -f "$ALLOC_FILE" ]; then
    JOBID=$(sed -n 's/^JOBID=//p' "$ALLOC_FILE" | head -1)
    # Numer z pliku moze byc MARTWY (poprzednia rezerwacja wygasla albo salloc padl
    # w trakcie i nie nadpisal pliku). Wtedy udajemy, ze pliku nie ma - ponizej
    # znajdzie sie zywa rezerwacja. Bez tego skrypt uparcie szukal nieistniejacego
    # zadania i konczyl sie bledem mimo dzialajacej rezerwacji.
    if [ -n "$JOBID" ] && ! squeue -h -j "$JOBID" -o %i >/dev/null 2>&1; then
      log "  $ALLOC_FILE wskazuje na nieistniejacy JOBID=$JOBID - szukam zywej rezerwacji"
      JOBID=""
    fi
  fi
  if [ -z "$JOBID" ]; then
    local running count
    # RUNNING i CONFIGURING: na DCC wezly budza sie ~3 min po przydziale i przez ten czas
    # zadanie jest w stanie CF - bez tego skrypt odpalony chwile po salloc nie widzial
    # rezerwacji ("Brak rezerwacji wezlow"). Na RUNNING i tak czekamy w petli nizej.
    running=$(squeue -u "$USER" -h -t RUNNING,CONFIGURING -o %i 2>/dev/null || true)
    count=$(printf '%s\n' "$running" | grep -c . || true)
    if [ "$count" = "1" ]; then
      JOBID="$running"
      log "Znalazlem Twoja rezerwacje JOBID=$JOBID - uzywam jej (nie zwolnie na koniec)"
    elif [ "$count" -gt 1 ]; then
      echo "!! Masz kilka dzialajacych rezerwacji - wskaz, ktorej uzyc:"
      squeue -u "$USER" -o "%.8i %.12j %.10M %.10L %R"
      echo "       JOBID=<numer> bash run_lan.sh"
      exit 1
    fi
  fi
  if [ -z "$JOBID" ]; then
    echo "!! Brak rezerwacji wezlow (squeue -u $USER nie pokazuje zadania RUNNING/CONFIGURING)."
    squeue -u "$USER" -o "%i %T %N" 2>/dev/null || true
    echo "   Ten skrypt tylko mierzy - wezly rezerwuje alloc.sh. Zrob najpierw:"
    echo "       bash alloc.sh"
    echo "   albo zrob salloc recznie, albo wskaz:  JOBID=<numer> bash run_lan.sh"
    exit 1
  fi

  local st
  st=$(squeue -h -j "$JOBID" -o %T 2>/dev/null || true)
  if [ -z "$st" ]; then
    echo "!! Rezerwacja JOBID=$JOBID nie istnieje (wygasla albo zostala zwolniona)."
    echo "   Zarezerwuj na nowo:  bash alloc.sh"
    exit 1
  fi
  # alloc.sh oddaje sterowanie dopiero w stanie RUNNING, ale przy JOBID= podanym
  # recznie wezly moga sie jeszcze budzic (stan CF/CONFIGURING) - poczekajmy.
  local t=0
  while [ "$st" != "RUNNING" ]; do
    sleep 2; t=$((t+2))
    [ "$t" -ge "$BOOT_TIMEOUT" ] && { echo "!! rezerwacja $JOBID w stanie '$st', nie RUNNING"; exit 1; }
    st=$(squeue -h -j "$JOBID" -o %T 2>/dev/null || true)
    [ -z "$st" ] && { echo "!! rezerwacja $JOBID zniknela"; exit 1; }
  done

  mapfile -t NODES < <(scontrol show hostnames "$(squeue -h -j "$JOBID" -o %N)")
  assign_nodes
  log "Wezly: ${NODES[*]}"
  log "  serwery (pula): ${SERVER_POOL[*]}"
  log "  klienci:        ${CLIENTS[*]}"
  local lay
  for lay in ${LAYOUTS[@]+"${LAYOUTS[@]}"}; do
    log "  uklad $(layout_tag "$lay"): $(layout_total "$lay") workerow (offsety: $(layout_offsets "$lay"))"
  done
  { echo "run_id=$RUN_ID"; echo "jobid=$JOBID"; echo "nodes=${NODES[*]}";
    echo "server_pool=${SERVER_POOL[*]}"; echo "clients=${CLIENTS[*]}";
    echo "layouts=$(layouts_pretty)";
    echo "sizes=$SIZES"; echo "transports=$TRANSPORTS";
    echo "conns=$CONNS repeats=$REPEATS"; echo "mode=rywrites clients_spec=$BENCH_CLIENTS";
    echo "payloads=$PAYLOADS requests=$REQUESTS warmup=$WARMUP";
    echo "appender_buffer=${APPENDER_BUFFER:-4MB(domyslne)}";
    echo "server_java_opts=${SERVER_JAVA_OPTS:-}";
    echo "quic_single_stream=$QUIC_SINGLE_STREAM";
    echo "hb_thread=$HB_THREAD fgap_ms=${FGAP_MS:-}";
    echo "rpc_timeout=${RPC_TIMEOUT:-150,300(domyslne)} no_prevote=$NO_PREVOTE";
    echo "readtput=$READTPUT readtput_clients=$READTPUT_CLIENTS readtput_payload=$READTPUT_PAYLOAD readtput_req=$READTPUT_REQ readtput_from=$READTPUT_FROM";
    echo "ram_log=$RAM_LOG storage_root=$STORAGE_ROOT";
  } > "$RESULTS/meta.txt"

  # Naglowek opisowy dla wyniki.csv: scal.sh wstawia go (liniami "# ...") na poczatku
  # pliku przy jego tworzeniu, zeby CSV sam mowil, czego dotyczy i w jakiej kolejnosci lecial.
  # NAGLOWEK_KEEP=1 (matrix6.sh): istniejacy naglowek opisuje CALA macierz - nie nadpisywac
  # go opisem pojedynczego kawalka.
  if [ "${NAGLOWEK_KEEP:-0}" = 1 ] && [ -f "$RESULTS/naglowek.txt" ]; then return 0; fi
  { echo "# Benchmark Raft-over-QUIC vs TCP+TLS (rywrites) - run_id=$RUN_ID start=$(date '+%Y-%m-%d %H:%M:%S')";
    echo "# serwery(pula): ${SERVER_POOL[*]}   klienci: ${CLIENTS[*]}";
    echo "# uklady klientow: $(layouts_pretty)";
    echo "# sizes: $SIZES | transports: $TRANSPORTS | conns: $CONNS | payloads: $PAYLOADS | requests/klienta: $REQUESTS | warmup: $WARMUP | repeats: $REPEATS";
    echo "# kolejnosc wykonania: sortuj po kolumnie seq; block=<nr>-<transport> to jeden cykl zycia serwerow (QUIC i TCP rozdzielone blokowo)";
    if [ "$QUIC_SINGLE_STREAM" = 1 ]; then
      echo "# WARIANT QUIC: jeden strumien na polaczenie serwer-serwer (CounterServer --single-stream, raft.quic.server.single-stream=true); TCP bez zmian; etykieta transportu w CSV to nadal QUIC - rozrozniaj po run_id";
    fi;
    if [ "$RAM_LOG" = 1 ]; then
      echo "# WARIANT KONTROLNY: log Rafta w pamieci (storage serwerow na tmpfs $STORAGE_ROOT, fsync natychmiastowy, BEZ trwalosci); oba transporty; obciazenie jak w macierzy glownej - rozrozniaj po run_id";
    fi;
    if [ "$HB_THREAD" = 1 ]; then
      echo "# WARIANT: heartbeaty z osobnego watku (CounterServer --hb-thread, raft.server.log.appender.heartbeat.thread=true); OBA transporty; heartbeat leci obok paczki/migawki zamiast po ich odpowiedzi - rozrozniaj po run_id";
    fi;
    if [ -n "${SERVER_JAVA_OPTS:-}" ]; then
      echo "# OPCJE SERWERA (SERVER_JAVA_OPTS, m.in. -Dratis.appender.buffer = rozmiar paczki AppendEntries): $SERVER_JAVA_OPTS";
    fi;
    if [ -n "$RPC_TIMEOUT" ] || [ "$NO_PREVOTE" = 1 ]; then
      echo "# WARIANT ELEKCJI: limit elekcji ${RPC_TIMEOUT:-150,300 (domyslny)} ms$([ "$NO_PREVOTE" = 1 ] && echo ', pre-vote WYLACZONE'); OBA transporty; elections = przejscia ->LEADER, candidate_attempts = przejscia FOLLOWER->CANDIDATE (z logow serwerow, delta na punkt)";
    fi;
  } > "$RESULTS/naglowek.txt"
}

# "1-1-1(=3w) 2-2-2(=6w)" - do meta.txt i naglowka CSV; "-" gdy tryb (a).
layouts_pretty() {
  local out="" lay
  for lay in ${LAYOUTS[@]+"${LAYOUTS[@]}"}; do
    out+="${out:+ }$(layout_tag "$lay")(=$(layout_total "$lay")w)"
  done
  echo "${out:--}"
}

# ---------------- 1b. PODZIAL WEZLOW NA SERWERY I KLIENTOW ----------------
in_nodes() { local x; for x in "${NODES[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }
is_client() { local x; for x in "${CLIENTS[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }

# Offsety --worker-offset dla kolejnych pozycji podanego ukladu (narastajaco), do logu.
layout_offsets() {   # $1 = uklad, np. "2 2 2 2 2"
  local off=0 out="" k
  for k in $1; do out+="${out:+ }$off"; off=$((off + k)); done
  echo "${out:--}"
}

assign_nodes() {
  local x
  # Klienci: jawna lista CLIENT_NODES albo OSTATNIE wezly alokacji
  # (ten sam sprzet klienta przy kazdym N -> porownywalnosc).
  if [ "${#CLIENT_NODES_ARR[@]}" -gt 0 ]; then
    for x in "${CLIENT_NODES_ARR[@]}"; do
      in_nodes "$x" || { echo "!! CLIENT_NODES: $x nie jest w rezerwacji (${NODES[*]})"; exit 1; }
    done
    CLIENTS=("${CLIENT_NODES_ARR[@]}")
  else
    if [ "${#NODES[@]}" -lt "$TOTAL_NODES" ]; then
      echo "!! Rezerwacja ma ${#NODES[@]} wezlow, a SIZES=\"$SIZES\" (+$NUM_CLIENT_NODES klient)"
      echo "   potrzebuje $TOTAL_NODES. Zmniejsz SIZES albo zarezerwuj wiecej:"
      echo "       bash alloc.sh free && NODES=$TOTAL_NODES bash alloc.sh"
      exit 1
    fi
    CLIENTS=("${NODES[@]: -NUM_CLIENT_NODES}")
  fi
  # Serwery: jawna lista SERVER_NODES albo wezly alokacji bez klientow, w kolejnosci alokacji.
  if [ "${#SERVER_NODES_ARR[@]}" -gt 0 ]; then
    for x in "${SERVER_NODES_ARR[@]}"; do
      in_nodes "$x"  || { echo "!! SERVER_NODES: $x nie jest w rezerwacji (${NODES[*]})"; exit 1; }
      is_client "$x" && { echo "!! $x jest jednoczesnie serwerem i klientem"; exit 1; }
    done
    SERVER_POOL=("${SERVER_NODES_ARR[@]}")
  else
    SERVER_POOL=()
    for x in "${NODES[@]}"; do
      if ! is_client "$x"; then SERVER_POOL+=("$x"); fi
    done
  fi
  if [ "${#SERVER_POOL[@]}" -lt "$MAX_N" ]; then
    echo "!! SIZES=\"$SIZES\" potrzebuje $MAX_N wezlow serwerowych, a do dyspozycji sa"
    echo "   ${#SERVER_POOL[@]}: ${SERVER_POOL[*]:-(zadne)}. Zarezerwuj wiecej albo zmniejsz SIZES."
    exit 1
  fi
  if [ "$LAYOUT_LEN" -gt 0 ] && [ "$LAYOUT_LEN" -ne "${#CLIENTS[@]}" ]; then
    echo "!! uklady maja $LAYOUT_LEN pozycji, a wezlow klienckich jest ${#CLIENTS[@]}: ${CLIENTS[*]}"
    exit 1
  fi
}

# Sprzatamy tylko PROCESY na wezlach - rezerwacja zostaje (zwalnia ja `alloc.sh free`).
# Procesy klienckie z trybu CLIENT_SPLIT zyja w tle na wezlach - po przerwaniu skryptu
# zostalyby i dopisywaly wiersze do CSV nastepnego przebiegu, dlatego bijemy oba wzorce
# na WSZYSTKICH wezlach (jednym przebiegiem, rownolegle).
cleanup() {
  local n
  local -a all=(${NODES[@]+"${NODES[@]}"})
  if [ "${#all[@]}" -gt 0 ]; then
    pssh "pkill -9 -f '[C]ounterServer'; pkill -9 -f '[R]aftBench'; true" "${all[@]}" || true
    # Zamykamy multipleksowane polaczenia - inaczej wisza jeszcze ControlPersist sekund
    # i trzymaja sockety w $SSH_CM_DIR.
    if [ "$SSH_MUX" = 1 ]; then
      for n in "${all[@]}"; do ssh "${SSH_OPTS[@]}" -O exit "$n" >/dev/null 2>&1 || true; done
    fi
  fi
}
# EXIT lapie normalne zakonczenie i blad; INT/TERM dokladamy jawnie, bo bez nich pojedynczy
# Ctrl+C potrafi ubic skrypt przed trapem i zostawic klientow, ktorzy - przez
# retryForeverNoSleep - nigdy nie kończą się same i obciazaja NASTEPNY przebieg.
trap cleanup EXIT INT TERM

# To samo PRZED startem: poprzedni przebieg mogl zostac przerwany tak, ze cleanup nie zdazyl.
# Bez tego nowy pomiar dzieli klaster z workerami poprzedniego i wyniki sa bezuzyteczne.
preclean() {
  local found
  found=$(pcount "pgrep -f '[C]ounterServer|[R]aftBench' >/dev/null 2>&1" "${NODES[@]}")
  if [ "$found" -gt 0 ]; then
    pssh "pkill -9 -f '[C]ounterServer'; pkill -9 -f '[R]aftBench'; true" "${NODES[@]}" || true
    log "  posprzatano procesy po poprzednim przebiegu na $found wezlach"
  fi
  return 0
}

# ---------------- 2. BOOT ----------------
# Wezly sprawdzamy NARAZ, nie po kolei: przy 9 wezlach sekwencyjna petla to 9 handshakow
# jeden po drugim. Przy okazji to tu powstaja polaczenia ControlMaster, z ktorych
# korzystaja wszystkie pozniejsze kroki.
wait_boot() {
  local node i=0 bad=0
  local -a pids=()
  for node in "${NODES[@]}"; do
    (
      t=0
      until ssh -n "${SSH_OPTS[@]}" "$node" true 2>/dev/null; do
        sleep 2; t=$((t+2))
        [ "$t" -ge "$BOOT_TIMEOUT" ] && exit 1
      done
    ) &
    pids+=($!)
  done
  for node in "${NODES[@]}"; do
    if ! wait "${pids[$i]}"; then echo "!! $node nie wstal w ${BOOT_TIMEOUT}s"; bad=1; fi
    i=$((i+1))
  done
  if [ "$bad" = 1 ]; then exit 1; fi
  log "  ${#NODES[@]} wezlow odpowiada na ssh"
}

# ---------------- 2b. KONTROLA tmpfs (tylko RAM_LOG=1) ----------------
# Na kazdym wezle z puli serwerow: STORAGE_ROOT musi byc tmpfs (inaczej "log w pamieci" bylby
# fikcja) i miec >= RAM_LOG_MIN_MB wolnego. Wynik idzie do logu i do meta.txt. Blad tutaj
# konczy przebieg PRZED startem serwerow - rezerwacja zostaje, nic na wezlach nie ruszylo.
check_ram_log() {
  local node fstype free_mb bad=0 f i
  local -a pids=() outs=()
  # Lokalnie rozwijaja sie tylko STORAGE_ROOT i USER; reszta (\$) wykonuje sie na wezle.
  local cmd="mkdir -p '$STORAGE_ROOT/$USER' 2>/dev/null; fs=\$(stat -f -c %T '$STORAGE_ROOT' 2>/dev/null || echo '?'); free=\$(df -Pk '$STORAGE_ROOT' 2>/dev/null | awk 'NR==2{print int(\$4/1024)}'); echo \"\$fs \${free:-0}\""
  for node in "${SERVER_POOL[@]}"; do
    f="$RESULTS/.shm_$node"
    sshx "$node" "$cmd" >"$f" 2>/dev/null &
    pids+=($!); outs+=("$f")
  done
  for i in ${pids[@]+"${pids[@]}"}; do wait "$i" || true; done
  i=0
  for node in "${SERVER_POOL[@]}"; do
    f="${outs[$i]}"; i=$((i+1))
    fstype=""; free_mb=""
    read -r fstype free_mb < "$f" 2>/dev/null || true
    rm -f "$f"
    fstype="${fstype:-?}"
    [[ "${free_mb:-}" =~ ^[0-9]+$ ]] || free_mb=0
    log "  $node: $STORAGE_ROOT = $fstype, wolne ${free_mb} MB"
    echo "ram_log_check $node fstype=$fstype free_mb=$free_mb" >> "$RESULTS/meta.txt"
    if [ "$fstype" != tmpfs ]; then
      echo "!! $node: $STORAGE_ROOT nie jest tmpfs ($fstype) - wariant 'log w pamieci' nie ma sensu"; bad=1
    fi
    if [ "$free_mb" -lt "$RAM_LOG_MIN_MB" ]; then
      echo "!! $node: tylko ${free_mb} MB wolnego na $STORAGE_ROOT (prog RAM_LOG_MIN_MB=$RAM_LOG_MIN_MB)"; bad=1
    fi
  done
  if [ "$bad" != 0 ]; then
    echo "   Nic nie wystartowalo. STORAGE_ROOT=<inny tmpfs> wskazuje inna sciezke, RAM_LOG_MIN_MB=0 wylacza prog miejsca."
    exit 1
  fi
  log "  tmpfs OK na ${#SERVER_POOL[@]} wezlach serwerowych (storage: $STORAGE_ROOT/$USER/raft/<transport>/n<N>)"
}

# ---------------- 3. conf.properties dla danego N (NFS home => widoczne wszedzie) ----------------
gen_conf() {   # $1 = N ; echo -> sciezka
  local n="$1" list="" i
  for ((i=0; i<n; i++)); do list+="${list:+,}${SERVER_POOL[$i]}:${PORT}"; done
  local f="$HOME/conf-n${n}.properties"
  # APPENDER_BUFFER: ile bajtow logu lider pakuje w JEDNO AppendEntries (domyslnie 4MB).
  # NIE zmienia obciazenia - klient dalej wysyla tyle samo. Zmienia tylko, jak dlugo
  # pojedyncza przesylka okupuje polaczenie do followera, czyli najdluzsza cisze na laczu.
  # Przy zapisach 1MB domyslne 4MB pakuje ~3 wpisy naraz (~160 ms ciszy przy ~19MB/s), a okno
  # elekcji zaczyna sie przy 150 ms (Rpc.TIMEOUT_MIN_DEFAULT). APPENDER_BUFFER=2MB wymusza
  # JEDEN wpis na przesylke (~53 ms), wiec heartbeat zdazy sie wcisnac miedzy paczki.
  # UWAGA: wartosc MUSI byc wieksza niz najwiekszy pojedynczy wpis. DataQueue.offer ma
  # assertTrue(elementNumBytes <= byteLimit) i przy mniejszym limicie lider rzuca wyjatkiem -
  # czyli przy ladunku 1MB nie wolno tu wpisac np. 256KB.
  { echo "# WYGENEROWANE przez run_lan.sh (run $RUN_ID) - nie edytuj recznie";
    echo "raft.server.address.list=${list}";
    if [ -n "${APPENDER_BUFFER:-}" ]; then
      echo "raft.server.log.appender.buffer.byte-limit=${APPENDER_BUFFER}"
    fi; } > "$f"
  cp "$f" "$RESULTS/conf-n${n}.properties"
  echo "$f"
}

# ---------------- 4. START SERWEROW ----------------
start_servers() {   # $1=N $2=transport $3=conf
  local n="$1" tr="$2" conf="$3" i node
  local flag=""; [ "$tr" = quic ] && flag="--quic"
  [ "$tr" = quic ] && [ "$QUIC_SINGLE_STREAM" = 1 ] && flag="--quic --single-stream"
  [ "$HB_THREAD" = 1 ] && flag="$flag --hb-thread"
  [ -n "$RPC_TIMEOUT" ] && flag="$flag --rpc-timeout=$RPC_TIMEOUT"
  [ "$NO_PREVOTE" = 1 ] && flag="$flag --no-prevote"
  local wd="$STORAGE_ROOT/$USER/raft/$tr/n$n"
  SERVERS=("${SERVER_POOL[@]:0:$n}")

  # Ubicie starego serwera i przygotowanie katalogu w JEDNYM ssh na wezel, wszystkie wezly
  # naraz (bylo: dwie sekwencyjne petle, czyli 2*N handshakow jeden po drugim).
  # '[C]ounterServer' zamiast 'CounterServer': bez nawiasu pkill -f zabija wlasna powloke,
  # bo jej linia polecen zawiera wzorzec (RUNBOOK §9) - dlatego moze siedziec w tej samej
  # komendzie co reszta. Petla pgrep czeka, az proces naprawde zniknie, zanim skasujemy
  # jego storage.
  # Kasowanie STAREGO storage n* jest krytyczne: log Raft z przebiegu o innym N ma inny
  # sklad grupy i serwer wystartowalby RECOVER na zlej konfiguracji.
  pssh "pkill -9 -f '[C]ounterServer' 2>/dev/null || true
        for k in 1 2 3 4 5 6 7 8 9 10; do
          pgrep -f '[C]ounterServer' >/dev/null 2>&1 || break
          sleep 0.3
        done
        mkdir -p '$wd' && ln -sfn '$HOME/ratis-test' '$wd/ratis-test' && rm -rf '$wd'/n*" \
    "${SERVERS[@]}"

  i=0
  for node in "${SERVERS[@]}"; do
    # indeks peera = POZYCJA W TABLICY (nie numer z nazwy hosta) - SLURM moze dac dowolne wezly.
    # sleep 86400 | java: CounterServer czeka na Scanner.nextLine(); puste stdin ubija go od razu.
    # ssh -f + przekierowania: bez nich skrypt zawisa na otwartym stdin/stdout (RUNBOOK §9).
    sshbg "$node" "cd '$wd' && RATIS_EXAMPLE_CONF='$conf' \
      nohup sh -c 'sleep 86400 | $JAVA $SERVER_JAVA_OPTS -cp $CP $SERVER_CLASS $i $flag' \
      </dev/null > 'server$i.log' 2>&1 &" >/dev/null 2>&1
    i=$((i+1))
  done
  log "  wystartowano $n serwerow ($tr${flag:+ $flag}) w $wd"
}

# ---------------- 5. GOTOWOSC ----------------
# log4j nie ma appendera => grep 'becomeLeader' NIE dziala. Dwustopniowo:
#   (a) gniazdo na kazdym wezle: ss -lnp bez -t/-u lapie TCP i UDP naraz,
#   (b) probny pelny cykl rywrites: zapis do lidera + odczyt wlasnego zapisu z followera.
wait_ready() {   # $1=N $2=transport $3=conf
  local n="$1" tr="$2" conf="$3" up=0 t0=$SECONDS waited=0 reported=0
  # Petla sprawdza NAJPIERW, spi tylko gdy jeszcze nie gotowe - przy normalnym starcie
  # wychodzi po paru sekundach. sock_timeout to tylko granica cierpliwosci.
  local sock_timeout="${SOCK_TIMEOUT:-120}"
  while :; do
    up=$(pcount "ss -lnp 2>/dev/null | grep -q ':$PORT'" "${SERVERS[@]}")
    [ "$up" -eq "$n" ] && break
    waited=$((SECONDS - t0))
    [ "$waited" -ge "$sock_timeout" ] && break
    if [ $((waited - reported)) -ge 30 ]; then
      reported=$waited; log "   ... nasluchuje $up/$n po ${waited}s"
    fi
    sleep 1
  done
  # return zamiast exit: przy dlugim przebiegu nieudany start JEDNEGO bloku nie moze
  # kosztowac wszystkich pozostalych - MAIN pomija blok i idzie dalej.
  [ "$up" -eq "$n" ] || { dump_logs "$n" "$tr"
    echo "!! nasluchuje tylko $up/$n serwerow na :$PORT (po ${waited}s)"; return 1; }

  # Probe robi RaftBench, a NIE CounterClient. CounterClient konczy zapis, po czym WISI
  # z zalozenia na linearizowalnym odczycie z followera (sendReadOnly -> ReadIndex), wiec
  # kazda proba kosztowala pelne 60 s timeoutu nawet wtedy, gdy klaster byl gotowy po 3 s -
  # to bylo zrodlo wiekszosci "minuty startu". RaftBench w trybie rywrites robi zapis do
  # lidera i STALE READ (minIndex=0) z followera, wypisuje 'Done.' i konczy sie sam w ~2 s.
  # Workerow bierzemy n-1: follower = id % liczba_followerow, wiec kazda replika dostaje
  # dokladnie jeden odczyt - probe sprawdza CALY klaster, a nie jedna replike jak dotad.
  local t=TCP_TLS; if [ "$tr" = quic ]; then t=QUIC; fi
  local probe="$RESULTS/probe_${tr}_n${n}.log"
  local workers=$((n - 1)) attempt=0
  [ "$workers" -lt 1 ] && workers=1
  local deadline=$((SECONDS + ${PROBE_TIMEOUT:-120}))
  while [ "$SECONDS" -lt "$deadline" ]; do
    attempt=$((attempt+1))
    # timeout na wypadek braku lidera: RaftBench ma retryForeverNoSleep i sam by nie wyszedl.
    sshx "${CLIENTS[0]}" "cd '$HOME' && RATIS_EXAMPLE_CONF='$conf' timeout ${PROBE_ATTEMPT:-30} \
          $CLIENT_JAVA -cp $CP $BENCH_CLASS --transport $t --mode rywrites --conn B \
          --clients $workers:$workers:1 --payload 64 --requests 1 --warmup 0" > "$probe" 2>&1 || true
    if grep -q '^Done\.' "$probe"; then
      log "  klaster gotowy (proba $attempt): $(grep -m1 'Leader = ' "$probe" || echo '?')"
      return 0
    fi
    sleep 2
  done
  dump_logs "$n" "$tr"
  echo "!! brak lidera lub niekompletny klaster (szczegoly: $probe)"; return 1
}

dump_logs() {   # $1=N $2=transport
  local n="$1" tr="$2" i=0 node p
  local -a pids=()
  for node in "${SERVERS[@]}"; do
    scp -q "${SSH_OPTS[@]}" "$node:$STORAGE_ROOT/$USER/raft/$tr/n$n/server$i.log" \
        "$RESULTS/${tr}_n${n}_server${i}.log" 2>/dev/null &
    pids+=($!)
    i=$((i+1))
  done
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || true; done
}

# ---------------- 5b. LICZNIKI Z LOGOW SERWEROW (elekcje + HOPSTAT) ----------------
# Migawka per punkt pomiarowy, brana PRZED i PO benchu (log serwera zyje przez caly cykl
# N x transport, wiec liczy sie delta):
#   - elekcje: linie "changes role from ... to LEADER" (RaftServerImpl, log4j.properties
#     wlacza INFO wlasnie dla tej klasy);
#   - HOPSTAT <follower> <count> <sum_ns>: skumulowany RTT AppendEntries lider->follower
#     (tylko RPC z danymi), wypisywany na stdout przez LogAppenderDefault co ~1 s.
# Sumujemy po WSZYSTKICH serwerach, nie tylko liderze - przy zmianie lidera w trakcie
# licznik starego zamarza, nowego rosnie, a suma delt dalej sie zgadza.
snapshot_servers() {   # $1=N $2=transport ; echo -> "elekcje kandydatury hop_count hop_sum_ns"
  local n="$1" tr="$2" i=0 node p f a b c d
  local -a pids=() outs=()
  for node in "${SERVERS[@]}"; do
    f="$RESULTS/.snap_${node}_$i"
    # Dwa niezalezne zrodla tych samych zdarzen (log4j na klastrze moze miec tylko jeden z
    # loggerow na INFO): RaftServerImpl ("changes role ...") i LeaderElection ("... PRE_VOTE/ELECTION
    # round 0: submit vote requests ...", "... ELECTION round N: result PASSED"). Bierzemy maksimum.
    # Proba = pierwsza faza elekcji: PRE_VOTE round 0 (pre-vote wlaczone) albo ELECTION round 0
    # (pre-vote wylaczone, wtedy PRE_VOTE nie wystepuje wcale).
    sshx "$node" "awk '/changes role from .* to LEADER/{r++}
                       /changes role from FOLLOWER to CANDIDATE/{a++}
                       /ELECTION round [0-9]+: result PASSED/{r2++}
                       /PRE_VOTE round 0: submit vote requests/{pv++}
                       /ELECTION round 0: submit vote requests/{el++}
                       /^HOPSTAT /{c[\$2]=\$3; s[\$2]=\$4}
                       END{C=0;S=0;for(k in c){C+=c[k];S+=s[k]};
                           a2=(pv>0)?pv:el; R=(r>r2)?r:r2; A=(a>a2)?a:a2; print R+0, A+0, C, S}' \
                      '$STORAGE_ROOT/$USER/raft/$tr/n$n/server$i.log' 2>/dev/null || echo '0 0 0 0'" \
      >"$f" 2>/dev/null &
    pids+=($!); outs+=("$f")
    i=$((i+1))
  done
  for p in ${pids[@]+"${pids[@]}"}; do wait "$p" || true; done
  local R=0 A=0 C=0 S=0
  for f in ${outs[@]+"${outs[@]}"}; do
    a=0; b=0; c=0; d=0
    read -r a b c d < "$f" 2>/dev/null || true
    R=$((R + ${a:-0})); A=$((A + ${b:-0})); C=$((C + ${c:-0})); S=$((S + ${d:-0}))
    rm -f "$f"
  done
  echo "$R $A $C $S"
}

# Po kazdym punkcie: delta migawek + srodowisko punktu do point_*.env i OD RAZU scalenie
# wynikow wielu procesow klienckich w jeden wiersz $RESULTS/wyniki.csv (scal.sh).
# Env zostaje na dysku, wiec scalanie mozna powtorzyc offline bez klastra:
#   for f in $RESULTS/point_*.env; do bash scal.sh "$f"; done
finish_point() {   # $1=N $2=transport $3=conn $4=payload $5=rep $6=snap0 $7=wall0 $8=finished
                   # $9=laytag $10=seq $11=block
  local n="$1" tr="$2" conn="$3" payload="$4" rep="$5" snap0="$6" wall0="$7" finished="$8"
  local laytag="${9:--}" seqno="${10:-0}" block="${11:--}"
  local t=TCP_TLS; [ "$tr" = quic ] && t=QUIC
  local snap1 e0 a0 c0 s0 e1 a1 c1 s1
  snap1=$(snapshot_servers "$n" "$tr")
  read -r e0 a0 c0 s0 <<<"$snap0"
  read -r e1 a1 c1 s1 <<<"$snap1"
  # Nazwy plikow niosa uklad ("-" = tryb (a) bez ukladow, wtedy nazwy jak w run_lan.sh,
  # zeby scal.sh dzialal na wynikach OBU skryptow bez rozgalezien).
  local key="${tr}_n${n}_${payload}_conn${conn}"
  local envf csvg latg
  if [ "$laytag" = "-" ]; then
    envf="$RESULTS/point_${key}_rep${rep}.env"
    csvg="${tr}_rywrites_conn${conn}*.csv"
    latg="lat_${key}_rep${rep}_*.txt"
  else
    envf="$RESULTS/point_${key}_${laytag}_rep${rep}.env"
    csvg="${tr}_rywrites_conn${conn}_${laytag}_*.csv"
    latg="lat_${key}_${laytag}_rep${rep}_*.txt"
  fi
  { echo "RUN_ID=$RUN_ID"; echo "REP=$rep"; echo "T=$t"; echo "N=$n";
    echo "PAYLOAD=$payload"; echo "CONN=$conn";
    echo "LAYOUT=$laytag"; echo "SEQ=$seqno"; echo "BLOCK=$block";
    echo "REQUESTS=$REQUESTS"; echo "WARMUP=$WARMUP";
    echo "ELECTIONS=$((e1 - e0))";
    echo "CANDIDATES=$((a1 - a0))";
    echo "HOP_SS_COUNT=$((c1 - c0))"; echo "HOP_SS_SUM_NS=$((s1 - s0))";
    echo "POINT_WALL_S=$((SECONDS - wall0))";
    echo "FINISHED=$finished";
    echo "CSV_GLOB=$csvg";
    echo "LAT_GLOB=$latg";
  } > "$envf"
  local scal
  scal="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/scal.sh"
  if [ -f "$scal" ]; then
    bash "$scal" "$envf" || log "  !! scal.sh nie zadzialal dla $envf (scal offline later)"
  else
    log "  !! brak scal.sh obok tego skryptu - punkt opisany w $envf, scal offline"
  fi
}

# ---------------- 6. BENCHMARK ----------------
run_bench() {   # $1=N $2=transport $3=conf $4=conn $5=payload $6=rep $7=uklad $8=seq $9=block
  local n="$1" tr="$2" conf="$3" conn="$4" payload="$5" rep="$6"
  local layout="${7:-}" seqno="${8:-0}" block="${9:--}"
  local t=TCP_TLS; [ "$tr" = quic ] && t=QUIC
  local laytag; laytag="$(layout_tag "$layout")"
  # Migawka licznikow serwerow PRZED benchem + zegar scienny punktu - z delty wychodza
  # kolumny elections i hop_server_server_ms oraz point_wall_s w wyniki.csv (finish_point).
  local snap0 wall0=$SECONDS
  snap0=$(snapshot_servers "$n" "$tr")

  if [ -z "$layout" ]; then
    # Tryb (a): jeden proces na pierwszym wezle klienckim (bez CLIENT_LAYOUTS/CLIENT_SPLIT).
    # Jeden CSV per (transport, conn). W wierszu: cluster_size rozroznia N, payload_bytes
    # rozroznia ladunek, rep powtorzenia, run_id przynaleznosc do tego przebiegu.
    local csv="$RESULTS/${tr}_rywrites_conn${conn}.csv"
    local lat="$RESULTS/lat_${tr}_n${n}_${payload}_conn${conn}_rep${rep}_${CLIENTS[0]}.txt"
    sshx "${CLIENTS[0]}" "cd '$HOME' && RATIS_EXAMPLE_CONF='$conf' $CLIENT_JAVA -cp $CP $BENCH_CLASS \
      --transport $t --mode rywrites --conn $conn --clients $BENCH_CLIENTS \
      --payload $payload --requests $REQUESTS --warmup $WARMUP \
      --run-id '$RUN_ID' --rep $rep --csv '$csv' --lat-file '$lat'" \
      | tee -a "$RESULTS/bench_${tr}_n${n}_conn${conn}.log"
    finish_point "$n" "$tr" "$conn" "$payload" "$rep" "$snap0" "$wall0" "1/1" \
      "-" "$seqno" "$block"
    return 0
  fi

  # Tryb (b): po jednym procesie na kazdym wezle klienckim, wszystkie naraz; podzial
  # workerow wg biezacego UKLADU. Osobny CSV na wezel - rownolegle dopisywanie do jednego
  # pliku na NFS przeplata wiersze. CSV i lat_* niosa uklad w nazwie: dwa uklady o tych
  # samych pozostalych parametrach nie moga ladowac w tym samym pliku, bo scal.sh (offline)
  # nie mialby jak ich odroznic - wiersz RaftBench nie zna ukladu.
  local i cnode k off=0 csv blog lat
  local -a split=() logs=()
  read -ra split <<<"$layout"
  for ((i=0; i<${#CLIENTS[@]}; i++)); do
    cnode="${CLIENTS[$i]}"; k="${split[$i]}"
    csv="$RESULTS/${tr}_rywrites_conn${conn}_${laytag}_${cnode}.csv"
    lat="$RESULTS/lat_${tr}_n${n}_${payload}_conn${conn}_${laytag}_rep${rep}_${cnode}.txt"
    blog="$RESULTS/bench_${tr}_n${n}_conn${conn}_${payload}_${laytag}_${cnode}_rep${rep}.log"
    # ssh -f + nohup + przekierowania na CALYM sh -c: bez nich skrypt zawisa (RUNBOOK §9).
    sshbg "$cnode" "cd '$HOME' && RATIS_EXAMPLE_CONF='$conf' \
      nohup sh -c '$CLIENT_JAVA -cp $CP $BENCH_CLASS --transport $t --mode rywrites --conn $conn \
        --clients $k:$k:1 --worker-offset $off --payload $payload --requests $REQUESTS \
        --warmup $WARMUP --run-id $RUN_ID --rep $rep --csv $csv --lat-file $lat' \
      </dev/null > '$blog' 2>&1 &" >/dev/null 2>&1 \
      || log "  !! ssh do $cnode nie wystartowal - punkt bedzie czesciowy"
    logs+=("$blog")
    off=$((off + k))
  done
  log "  wystartowano ${#CLIENTS[@]} procesow klienckich (uklad $laytag), czekam..."
  # Podglad na zywo. Logi klientow pisza sie do $RESULTS, czyli na NFS-owy $HOME - wezel
  # dostepowy widzi je natychmiast. Bez tego postep widac dopiero w koncowym CSV i nie da
  # sie odroznic "wolno" od "wisi". Naglowki '==> plik <==' od tail pokazuja, ktory wezel.
  # LIVE=0 wylacza podglad.
  local livepid=""
  if [ "${LIVE:-1}" = 1 ]; then
    tail -n0 -F "${logs[@]}" 2>/dev/null \
      | grep --line-buffered -E 'worker |failed|Exception|^==> ' &
    livepid=$!
  fi
  local timedout=0
  wait_clients || timedout=1
  if [ -n "$livepid" ]; then
    kill "$livepid" >/dev/null 2>&1 || true
    wait "$livepid" >/dev/null 2>&1 || true
  fi
  for blog in "${logs[@]}"; do
    echo "--- $(basename "$blog") ---"
    cat "$blog" 2>/dev/null || echo "(brak logu - ssh do wezla nie wystartowal?)"
  done
  check_consistent "$n" "$tr" "$payload" "$conn" "$rep" "$laytag" "${logs[@]}"
  if [ "$timedout" = 1 ]; then
    echo "seq=$seqno blok=$block N=$n $tr payload=$payload conn=$conn layout=$laytag rep=$rep" \
         "TIMEOUT po ${BENCH_TIMEOUT}s - klienci ubici, punkt niepelny" >> "$RESULTS/ODRZUCONE.txt"
  fi
  finish_point "$n" "$tr" "$conn" "$payload" "$rep" "$snap0" "$wall0" "$CHECK_RESULT" \
    "$laytag" "$seqno" "$block"
}

# READTPUT=1: sami czytelnicy na zywym klastrze bloku (patrz opis przy zmiennej READTPUT).
run_readtput() {   # $1=N $2=transport $3=conf
  local n="$1" tr="$2" conf="$3" i cnode csv blog
  local t=TCP_TLS; [ "$tr" = quic ] && t=QUIC
  local -a logs=() csvs=()
  log "  readtput: sami czytelnicy, $tr, $READTPUT_PAYLOAD z $READTPUT_FROM, $READTPUT_CLIENTS na wezel x ${#CLIENTS[@]} wezlow, $READTPUT_REQ odczytow/czytelnika"
  for ((i=0; i<${#CLIENTS[@]}; i++)); do
    cnode="${CLIENTS[$i]}"
    csv="$RESULTS/readtput_${tr}_n${n}_${cnode}.csv"
    blog="$RESULTS/readtput_${tr}_n${n}_${cnode}.log"
    rm -f "$csv"
    sshbg "$cnode" "cd '$HOME' && RATIS_EXAMPLE_CONF='$conf' \
      nohup sh -c '$CLIENT_JAVA -cp $CP $BENCH_CLASS --transport $t --mode scaling --read-ratio 1.0 \
        --read-from $READTPUT_FROM --conn B --clients $READTPUT_CLIENTS --payload $READTPUT_PAYLOAD \
        --requests $READTPUT_REQ --warmup $WARMUP --run-id $RUN_ID --rep 1 --csv $csv' \
      </dev/null > '$blog' 2>&1 &" >/dev/null 2>&1 \
      || log "  !! readtput: ssh do $cnode nie wystartowal"
    logs+=("$blog"); csvs+=("$csv")
  done
  wait_clients || { log "  !! readtput: TIMEOUT, procesy ubite"; }
  # Scalenie: wiersze o tym samym numerze (ten sam krok OD:DO:KROK) z kazdego procesu:
  # czytelnicy i przepustowosc sumowane, p50/srednia usredniane, p99 maksimum.
  local out="$RESULTS/readtput.csv"
  [ -f "$out" ] || echo "run_id,block,transport,cluster_size,payload_bytes,read_from,readers_total,read_tput_req_s,read_MB_s,read_p50_ms_mean,read_p99_ms_max,read_mean_ms_mean,reads_ok,reads_failed,procs" > "$out"
  awk -F, -v RID="$RUN_ID" -v BLK="$BLOCK" -v OUT="$out" '
    FNR == 1 { for (i = 1; i <= NF; i++) ix[$i] = i; next }
    {
      k = FNR
      tr[k] = $ix["transport"]; n[k] = $ix["cluster_size"]; pb[k] = $ix["payload_bytes"]; rf[k] = $ix["read_from"]
      readers[k] += $ix["readers"]; tput[k] += $ix["read_tput_req_s"]; mbs[k] += $ix["read_MB_s"]
      p50[k] += $ix["read_p50_ms"]; mean[k] += $ix["read_mean_ms"]
      if ($ix["read_p99_ms"] + 0 > p99[k] + 0) p99[k] = $ix["read_p99_ms"]
      ok[k] += $ix["reads_ok"]; bad[k] += $ix["reads_failed"]; procs[k]++
      if (k > maxk) maxk = k
    }
    END {
      for (k = 2; k <= maxk; k++) if (procs[k] > 0)
        printf "%s,%s,%s,%s,%s,%s,%d,%.1f,%.2f,%.3f,%.3f,%.3f,%d,%d,%d\n", RID, BLK, tr[k], n[k], pb[k], rf[k],
          readers[k], tput[k], mbs[k], p50[k] / procs[k], p99[k], mean[k] / procs[k], ok[k], bad[k], procs[k] >> OUT
    }' "${csvs[@]}" 2>/dev/null || log "  !! readtput: scalenie nie zadzialalo (surowe CSV zostaja)"
  log "  readtput: $(tail -1 "$out")"
}

# Bariera: czeka, az RaftBench zniknie z KAZDEGO wezla klienckiego.
# '[R]aftBench' zamiast 'RaftBench': bez nawiasu pgrep -f dopasowalby wlasna powloke ssh
# (jej linia polecen zawiera wzorzec) i petla nigdy by sie nie skonczyla - ta sama pulapka
# co pkill -f CounterServer (RUNBOOK §9).
wait_clients() {
  # waited liczymy z $SECONDS, a nie sumujac sleepy: samo odpytanie wezlow tez trwa,
  # wiec stary licznik zanizal czas (i BENCH_TIMEOUT wypadal grubo pozniej niz mial).
  local running t0=$SECONDS waited=0 reported=0
  sleep 3   # ssh -f wraca chwile PRZED startem zdalnego polecenia - nie sprawdzaj od razu
  while :; do
    running=$(pcount "pgrep -f '[R]aftBench' >/dev/null 2>&1" "${CLIENTS[@]}")
    [ "$running" -eq 0 ] && return 0
    sleep 3; waited=$((SECONDS - t0))
    if [ $((waited - reported)) -ge 60 ]; then
      reported=$waited; log "   ... dziala jeszcze $running/${#CLIENTS[@]} procesow (${waited}s)"
    fi
    if [ "$waited" -ge "$BENCH_TIMEOUT" ]; then
      pssh "pkill -9 -f '[R]aftBench'; true" "${CLIENTS[@]}" || true
      echo "!! procesy klienckie nie skonczyly w ${BENCH_TIMEOUT}s - ubite. Logi: $RESULTS/bench_*"
      echo "   conn A z wieloma klientami trwa dlugo - podnies BENCH_TIMEOUT albo zmniejsz REQUESTS."
      # NIE przerywamy sweepu: przy przebiegu na kilka godzin jeden zacinajacy sie punkt
      # nie moze kosztowac wszystkich pozostalych. Punkt idzie do ODRZUCONE.txt, a to, co
      # klienci zdazyli zapisac, i tak zostanie scalone (widac po clients_total/requests_sent).
      return 1
    fi
  done
}

# Przy jednym procesie widac golym okiem, czy 'Leader = nX, Followers = [...]' jest kompletne.
# Przy kilku trzeba sprawdzic maszynowo, ze WSZYSTKIE widzialy ten sam klaster i doszly do
# 'Done.' - inaczej w CSV laduje wiersz z przebiegu, ktory nie jest porownywalny z reszta.
# Nie przerywamy sweepu (rezerwacja jest krotka) - wpis do ODRZUCONE.txt, a wiersz zostaje,
# zeby dalo sie go odfiltrowac po run_id/rep.
check_consistent() {   # $1=N $2=transport $3=payload $4=conn $5=rep $6=uklad $7..=logi
  local n="$1" tr="$2" payload="$3" conn="$4" rep="$5" laytag="$6"; shift 6
  local f finished=0 leaders
  for f in "$@"; do
    if grep -q '^Done\.' "$f"; then finished=$((finished+1)); fi
  done
  CHECK_RESULT="$finished/$#"   # dla finish_point: ile procesow doszlo do konca (kolumna w env)
  leaders=$(grep -h 'Leader = ' "$@" | sort -u | grep -c . || true)
  if [ "$finished" -eq $# ] && [ "$leaders" -eq 1 ]; then
    log "  OK: $# procesow, ten sam lider, wszystkie doszly do konca"
    return 0
  fi
  echo "!! NIESPOJNY przebieg N=$n $tr payload=$payload conn=$conn uklad=$laytag rep=$rep:"
  echo "   do konca doszlo $finished/$# procesow, roznych linii 'Leader =': $leaders"
  grep -H 'Leader = ' "$@" || true
  echo "N=$n transport=$tr payload=$payload conn=$conn layout=$laytag rep=$rep finished=$finished/$# leaders=$leaders" \
    >> "$RESULTS/ODRZUCONE.txt"
}

# ---------------- MAIN ----------------
# Petla: N { transport { payload { conn { UKLAD { rep } } } } }
# - transport wysoko = osobne BLOKI serwerowe (restart klastra); w CSV block=<nr>-<transport>,
#   wiec rozdzial QUIC/TCP widac wprost, a seq daje chronologie;
# - uklady leca bezposrednio po sobie (te same warunki klastra) - to je porownujesz;
# - rep najnizej, bo z powtorzen liczy sie mediane.
# LAYS_ITER: pusta lista ukladow = jedna iteracja trybu (a) (jeden proces, BENCH_CLIENTS).
if [ "${#LAYOUTS[@]}" -eq 0 ]; then LAYS_ITER=(""); else LAYS_ITER=("${LAYOUTS[@]}"); fi
EST_POINT_S="${EST_POINT_S:-90}"

# DRYRUN=1: pelna lista punktow w kolejnosci wykonania + szacunek czasu, zero dotykania
# klastra (wychodzi PRZED use_allocation, wiec nie potrzebuje nawet rezerwacji).
if [ "$DRYRUN" = 1 ]; then
  echo "== PLAN PRZEBIEGU (DRYRUN) =="
  [ "$QUIC_SINGLE_STREAM" = 1 ] && echo "== wariant QUIC: jeden strumien na polaczenie serwer-serwer (--single-stream); TCP bez zmian"
  [ "$RAM_LOG" = 1 ] && echo "== wariant KONTROLNY: log w pamieci (storage serwerow na tmpfs $STORAGE_ROOT, bez trwalosci); oba transporty"
  [ "$HB_THREAD" = 1 ] && echo "== wariant: heartbeaty z osobnego watku (--hb-thread); oba transporty"
  [ -n "$RPC_TIMEOUT" ] && echo "== wariant: limit elekcji $RPC_TIMEOUT ms (--rpc-timeout); oba transporty"
  [ "$NO_PREVOTE" = 1 ] && echo "== wariant: pre-vote wylaczone (--no-prevote); oba transporty"
  [ "$READTPUT" = 1 ] && echo "== dodatkowo po kazdym bloku: sami czytelnicy ($READTPUT_PAYLOAD z $READTPUT_FROM, $READTPUT_CLIENTS/wezel, $READTPUT_REQ odczytow) -> readtput.csv"
  SEQ_NO=$SEQ0; BLOCK_NO=$BLOCK0
  for N in $SIZES; do
    for TR in $TRANSPORTS; do
      BLOCK_NO=$((BLOCK_NO+1))
      echo "-- blok $BLOCK_NO-$TR: N=$N, restart serwerow (~70 s)"
      for PL in $PAYLOADS; do for CONN in $CONNS; do
        for LAY in "${LAYS_ITER[@]}"; do
          for REP in $(seq 1 "$REPEATS"); do
            SEQ_NO=$((SEQ_NO+1))
            printf '   seq=%-3s payload=%-6s conn=%s uklad=%-12s workerow=%-3s rep=%s/%s\n' \
              "$SEQ_NO" "$PL" "$CONN" "$(layout_tag "$LAY")" \
              "$([ -n "$LAY" ] && layout_total "$LAY" || echo "${BENCH_CLIENTS%%:*}")" "$REP" "$REPEATS"
          done
        done
      done; done
    done
  done
  EST=$((BLOCK_NO * 70 + SEQ_NO * EST_POINT_S))
  echo "== punktow: $SEQ_NO, blokow serwerowych: $BLOCK_NO"
  echo "== szacunek: $BLOCK_NO x 70 s startu + $SEQ_NO x ${EST_POINT_S} s/punkt ~= $((EST / 60)) min"
  echo "   (czas punktu zalezy od payload/conn/ukladu - nadpisz EST_POINT_S=; rezerwacja SLURM to 30 min)"
  exit 0
fi

use_allocation
tic; wait_boot; toc "ssh do wezlow"
if [ "$RAM_LOG" = 1 ]; then tic; check_ram_log; toc "kontrola tmpfs (RAM_LOG=1)"; fi
tic; preclean;  toc "sprzatanie po poprzednim przebiegu"
SEQ_NO=$SEQ0; BLOCK_NO=$BLOCK0
for N in $SIZES; do
  CONF="$(gen_conf "$N")"
  for TR in $TRANSPORTS; do
    BLOCK_NO=$((BLOCK_NO+1)); BLOCK="$BLOCK_NO-$TR"
    log "=== blok $BLOCK: N=$N transport=$TR ==="
    PHASE_T0=$SECONDS
    tic; start_servers "$N" "$TR" "$CONF"; toc "start serwerow"
    # Nieudany start bloku POMIJA blok, nie ubija przebiegu: przy sweepie na kilka godzin
    # jeden niewstajacy klaster nie moze kosztowac wszystkich pozostalych punktow.
    # Wyniki juz zmierzonych punktow leza w wyniki.csv (scal.sh po KAZDYM punkcie).
    tic
    if ! wait_ready "$N" "$TR" "$CONF"; then
      toc "gotowosc klastra (NIEUDANA - blok pominiety)"
      log "  !! blok $BLOCK pominiety: klaster nie wstal. Ide do nastepnego bloku."
      echo "blok=$BLOCK N=$N transport=$TR POMINIETY: klaster nie wstal" >> "$RESULTS/ODRZUCONE.txt"
      pssh "pkill -9 -f '[C]ounterServer'; true" "${SERVERS[@]}" || true
      continue
    fi
    toc "gotowosc klastra (gniazda + probe)"
    log "  [czas] RAZEM od zera do pierwszego benchu: $((SECONDS - PHASE_T0))s"
    for PL in $PAYLOADS; do
      for CONN in $CONNS; do
        for LAY in "${LAYS_ITER[@]}"; do
          for REP in $(seq 1 "$REPEATS"); do
            SEQ_NO=$((SEQ_NO+1))
            log "  bench seq=$SEQ_NO blok=$BLOCK N=$N $TR payload=$PL conn=$CONN uklad=$(layout_tag "$LAY") rep=$REP/$REPEATS"
            if ! run_bench "$N" "$TR" "$CONF" "$CONN" "$PL" "$REP" "$LAY" "$SEQ_NO" "$BLOCK"; then
              log "  !! punkt seq=$SEQ_NO NIEUDANY - ide do nastepnego"
              echo "seq=$SEQ_NO N=$N transport=$TR payload=$PL conn=$CONN layout=$(layout_tag "$LAY") rep=$REP PUNKT NIEUDANY (blad harnessu)" \
                >> "$RESULTS/ODRZUCONE.txt"
              pssh "pkill -9 -f '[R]aftBench'; true" "${CLIENTS[@]}" || true
            fi
          done
        done
      done
    done
    if [ "$READTPUT" = 1 ]; then tic; run_readtput "$N" "$TR" "$CONF"; toc "readtput (sami czytelnicy)"; fi
    dump_logs "$N" "$TR"
    pssh "pkill -9 -f '[C]ounterServer'; true" "${SERVERS[@]}" || true
    if [ "$RAM_LOG" = 1 ]; then
      # tmpfs to RAM wezla: logi serwerow sa juz skopiowane do $RESULTS, wiec storage bloku
      # (katalogi n*) kasujemy od razu, zeby nastepny blok/przebieg nie zaczynal z mniejsza pamiecia.
      pssh "rm -rf '$STORAGE_ROOT/$USER/raft/$TR/n$N'/n*" "${SERVERS[@]}" || true
      log "  storage bloku na tmpfs skasowany"
    fi
  done
done
echo "sweep_elapsed_s=$SECONDS" >> "$RESULTS/meta.txt"
ROWS=0
WYNIKI_CSV="${WYNIKI_CSV:-wyniki.csv}"
[ -f "$RESULTS/$WYNIKI_CSV" ] && ROWS=$(grep -vc '^#\|^run_id,' "$RESULTS/$WYNIKI_CSV" || true)
log "Gotowe w ${SECONDS}s: $((SEQ_NO - SEQ0)) punktow w tym przebiegu, $ROWS wierszy w $WYNIKI_CSV"
if [ -f "$RESULTS/ODRZUCONE.txt" ]; then
  log "  UWAGA: sa punkty z zastrzezeniami - $RESULTS/ODRZUCONE.txt ($(wc -l < "$RESULTS/ODRZUCONE.txt") wpisow)"
fi
