# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.

# syntax=docker/dockerfile:1.4

# ── Stage 1: build ────────────────────────────────────────────────────────────
# Run the Maven build on linux/arm64 so os-maven-plugin detects linux-aarch_64
# and the netty-incubator-codec-native-quic:linux-aarch_64 native binary is
# pulled from Maven Central and embedded in the fat JAR.  Without this the JVM
# would throw UnsatisfiedLinkError when loading the QUIC codec.
FROM --platform=linux/arm64 maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /src
COPY . .

# --mount=type=cache keeps the local Maven repository between builds.
# Even when COPY . . is a cache miss (e.g. a script in docker/ changed),
# Maven finds its dependencies already downloaded and finishes in seconds.
RUN --mount=type=cache,target=/root/.m2,sharing=locked \
    mvn -pl ratis-examples -am \
        -DskipTests \
        -Dcheckstyle.skip=true \
        -Dspotbugs.skip=true \
        -Dlicense.skip=true \
        --no-transfer-progress \
        package

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM --platform=linux/arm64 eclipse-temurin:21-jre

# iptables / iproute2 are required for network-partition simulation.
# openssl is required to generate TLS certificates with correct Docker SANs.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables iproute2 openssl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Fat JAR (all deps, including native quiche .so for linux-aarch_64)
COPY --from=builder \
    /src/ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar \
    /app/ratis-examples.jar

# Log4j config
COPY --from=builder \
    /src/ratis-examples/src/main/resources/log4j.properties \
    /app/log4j.properties

# Certificate generator — creates certs with SANs for n0/n1/n2/client/localhost.
# The original repo certs have CN=localhost and no SANs, which causes TLS
# handshake failures when Netty connects between Docker containers by hostname.
COPY docker/gen-certs.sh /gen-certs.sh
RUN chmod +x /gen-certs.sh && \
    mkdir -p /app/ratis-test/src/test/resources/ssl && \
    /gen-certs.sh

# Server entrypoint (kept separate so the client service can override ENTRYPOINT)
COPY docker/entrypoint-server.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
