# Uruchamianie benchmarku QUIC vs TCP w Dockerze

## Wymagania

- Docker Desktop (Apple Silicon — domyślnie `linux/arm64`, nie trzeba nic zmieniać)
- `docker compose` v2 (wbudowany w Docker Desktop)
- Wszystkie komendy uruchamiaj z **root katalogu repo** (`raft-over-quic/`)

---

## Krok 1 — zbuduj obraz i wystaw klaster

Wybierz transport i uruchom:

```bash
# Wariant QUIC
TRANSPORT=quic docker compose -f docker/docker-compose.yml up --build -d

# Wariant Netty/TCP
TRANSPORT=netty docker compose -f docker/docker-compose.yml up --build -d
```

> Pierwsze `--build` trwa ~5–10 min (Maven pobiera zależności).
> Kolejne uruchomienia bez `--build` są natychmiastowe.

Sprawdź czy węzły żyją:

```bash
docker compose -f docker/docker-compose.yml ps
```

Poczekaj ~8 sekund na elekcję lidera, a potem sprawdź logi:

```bash
docker compose -f docker/docker-compose.yml logs n0
# szukaj linii z "LEADER" lub "becomes Leader"
```

---

## Krok 2 — uruchom klienta

```bash
# QUIC — 10 inkrementów
docker compose -f docker/docker-compose.yml exec client \
  java -cp /app/ratis-examples.jar \
  -Dlog4j.configuration=file:/app/log4j.properties \
  org.apache.ratis.examples.counter.client.CounterClient \
  10 IO --quic

# Netty/TCP — bez --quic
docker compose -f docker/docker-compose.yml exec client \
  java -cp /app/ratis-examples.jar \
  -Dlog4j.configuration=file:/app/log4j.properties \
  org.apache.ratis.examples.counter.client.CounterClient \
  10 IO
```

---

## Krok 3 — test partycji sieciowej

### Odetnij n2 (bez RST — pakiety cichutko lecą w /dev/null)

```bash
docker compose -f docker/docker-compose.yml exec n2 iptables -A INPUT  -j DROP
docker compose -f docker/docker-compose.yml exec n2 iptables -A OUTPUT -j DROP
```

### Zmierz czas otrząśnięcia klienta

```bash
# QUIC
time docker compose -f docker/docker-compose.yml exec client \
  java -cp /app/ratis-examples.jar \
  -Dlog4j.configuration=file:/app/log4j.properties \
  org.apache.ratis.examples.counter.client.CounterClient \
  1 IO --quic

# Netty/TCP
time docker compose -f docker/docker-compose.yml exec client \
  java -cp /app/ratis-examples.jar \
  -Dlog4j.configuration=file:/app/log4j.properties \
  org.apache.ratis.examples.counter.client.CounterClient \
  1 IO
```

`time` pokaże ile sekund minęło zanim klient dostał odpowiedź od klastra (n0+n1 mają kworum).

### Przywróć n2

```bash
docker compose -f docker/docker-compose.yml exec n2 iptables -F
```

n2 dogoni log — w logach pojawi się `catching up`.

---

## Krok 4 — zatrzymanie i reset

```bash
# Zatrzymaj kontenery (zachowaj dane)
docker compose -f docker/docker-compose.yml down

# Zatrzymaj i wyczyść wolumeny (świeży start)
docker compose -f docker/docker-compose.yml down -v
```

---

## Przełączanie między QUIC a TCP

Żeby porównać oba transporty w tej samej sesji:

```bash
# 1. Zatrzymaj i wyczyść
docker compose -f docker/docker-compose.yml down -v

# 2. Wystaw na innym transporcie
TRANSPORT=netty docker compose -f docker/docker-compose.yml up -d
# (obraz już zbudowany, -d bez --build)
```

---

## Skrócone aliasy (opcjonalnie wklej do ~/.zshrc)

```bash
alias raft='docker compose -f $(git rev-parse --show-toplevel)/docker/docker-compose.yml'

# Użycie:
TRANSPORT=quic raft up --build -d
raft exec client java -cp /app/ratis-examples.jar \
  org.apache.ratis.examples.counter.client.CounterClient 10 IO --quic
raft down -v
```
