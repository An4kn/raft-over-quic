#!/bin/bash

JAR="ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar"
CLIENT="org.apache.ratis.examples.counter.client.CounterClient"
SERVER="org.apache.ratis.examples.counter.server.CounterServer"
LOG="-Dlog4j.configuration=file:ratis-examples/src/main/resources/log4j.properties"

# Argument: --quic lub --netty (domyslnie --quic)
TRANSPORT="--quic"
for arg in "$@"; do
  if [[ "$arg" == "--netty" ]]; then
    TRANSPORT=""
  elif [[ "$arg" == "--quic" ]]; then
    TRANSPORT="--quic"
  fi
done

echo "Transport: ${TRANSPORT:+QUIC}${TRANSPORT:-Netty/TCP}"

run_client() {
  java $LOG -cp "$JAR" $CLIENT "$@" $TRANSPORT
}

start_server() {
  local index=$1
  # <(cat) trzyma stdin otwarty bez blokowania terminala
  java $LOG -cp "$JAR" $SERVER $index $TRANSPORT < <(cat) >server${index}.log 2>&1 &
  echo $!
}

kill_server() {
  local pid=$1
  local name=$2
  echo "Zabijam serwer ${name} (PID: $pid)..."
  kill -9 $pid 2>/dev/null
}

echo "============================================"
echo "Raft Counter Test Suite"
echo "============================================"
echo ""

echo "Uruchamiam 3 serwery..."
PID0=$(start_server 0)
PID1=$(start_server 1)
PID2=$(start_server 2)
echo "PIDs: n0=$PID0 n1=$PID1 n2=$PID2"
echo "Czekam 8s na elekcje lidera..."
sleep 8

echo ""
echo "=== TEST 1: Podstawowe dzialanie ==="
run_client 10 IO
echo ""

echo "=== TEST 2: Sprawdzam wartosc licznika (powinno byc 10) ==="
run_client 0 IO
echo ""

echo "=== TEST 3: Awaria followera (n1) ==="
kill_server $PID1 "n1"
sleep 2
echo "Wysylam 5 incrementow po awarii followera..."
run_client 5 IO
echo "=> Klaster powinien dzialac (kworum 2/3)"
echo ""

echo "=== TEST 4: Awaria lidera (n0) ==="
kill_server $PID0 "n0"
echo "Czekam 4s na re-elekcje..."
sleep 4
echo "Wysylam 5 incrementow po awarii lidera..."
run_client 5 IO
echo "=> Nowy lider (n2) powinien obsluzyc requesty"
echo ""

echo "=== TEST 5: Finalny licznik (powinno byc 20) ==="
run_client 0 IO
echo ""

echo "=== TEST 6: Wznowienie n0 i n1 ==="
PID1=$(start_server 1)
sleep 3
PID0=$(start_server 0)
sleep 3
echo "Wysylam 5 incrementow po wznowieniu..."
run_client 5 IO
echo ""

echo "=== TEST 7: Finalny licznik po wznowieniu (powinno byc 25) ==="
run_client 0 IO
echo ""

echo "============================================"
echo "Testy zakonczone. Zatrzymuje serwery..."
kill -9 $PID0 $PID1 $PID2 2>/dev/null
echo "Logi: server0.log, server1.log, server2.log"
echo "============================================"
