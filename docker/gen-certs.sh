#!/bin/sh
set -e
OUT=/app/ratis-test/src/test/resources/ssl
EXT="$OUT/san.ext"

# SAN extension — covers Docker service names, localhost, and 127.0.0.1
echo "subjectAltName=DNS:localhost,DNS:n0,DNS:n1,DNS:n2,DNS:client,IP:127.0.0.1" > "$EXT"

# CA
openssl genrsa -out "$OUT/ca.key" 2048
openssl req -new -x509 -days 3650 -key "$OUT/ca.key" -out "$OUT/ca.crt" \
  -subj "/CN=ratis-ca"

# Server cert
openssl genrsa -out "$OUT/server.key" 2048
openssl req -new -key "$OUT/server.key" -out "$OUT/server.csr" -subj "/CN=ratis-server"
openssl x509 -req -days 3650 \
  -in "$OUT/server.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -extfile "$EXT" -out "$OUT/server.crt"
openssl pkcs8 -topk8 -nocrypt -in "$OUT/server.key" -out "$OUT/server.pem"

# Client cert (server-as-client peer connections)
openssl genrsa -out "$OUT/client.key" 2048
openssl req -new -key "$OUT/client.key" -out "$OUT/client.csr" -subj "/CN=ratis-client"
openssl x509 -req -days 3650 \
  -in "$OUT/client.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -out "$OUT/client.crt"
openssl pkcs8 -topk8 -nocrypt -in "$OUT/client.key" -out "$OUT/client.pem"

rm "$EXT"
echo "Certs OK"
