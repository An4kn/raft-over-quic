#!/bin/sh
set -e

# Named pipe keeps Scanner(System.in).nextLine() blocked forever.
# The write end must be opened BEFORE exec-ing Java, otherwise the
# kernel blocks the open(O_RDONLY) call until a writer appears.
KEEPALIVE=/tmp/keepalive
rm -f "$KEEPALIVE"
mkfifo "$KEEPALIVE"
tail -f /dev/null > "$KEEPALIVE" &

QUIC_FLAG=""
if [ "${TRANSPORT:-quic}" = "quic" ]; then
  QUIC_FLAG="--quic"
fi

exec java \
  -Dlog4j.configuration=file:/app/log4j.properties \
  -cp /app/ratis-examples.jar \
  org.apache.ratis.examples.counter.server.CounterServer \
  "${PEER_INDEX}" ${QUIC_FLAG} < "$KEEPALIVE"
