#!/bin/bash

SERVER="org.apache.ratis.examples.counter.server.CounterServer"

echo "Zatrzymuje serwery..."
PIDS=$(jps -l | grep $SERVER | awk '{print $1}')
if [[ -n "$PIDS" ]]; then
  kill -9 $PIDS
  echo "Zabito PID: $PIDS"
else
  echo "Brak uruchomionych serwerow."
fi

echo "Czyszcze storage (n0, n1, n2)..."
rm -rf n0 n1 n2
echo "Gotowe. Mozesz uruchomic serwery od nowa."
