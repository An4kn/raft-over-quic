# Benchmark: QUIC vs Netty w Apache Ratis

Skrypty do porównania transportów QUIC i Netty/TCP w klastrze Apache Ratis (N węzłów — liczba
serwerów wynika z długości `raft.server.address.list`; przykład Counter).
Działają zarówno w środowisku Docker jak i na prawdziwych maszynach Linux.

---

## Testy

| # | Test | Opis |
|---|------|------|
| 1 | **Baseline** | 3 × 5 inkrementów bez awarii, mediana czasu |
| 2 | **Awaria followera / nowy klient** | DROP followera → nowy klient wysyła 5 inkrementów |
| 3 | **Awaria lidera / nowy klient** | DROP lidera → nowy klient wysyła 5 inkrementów (musi odkryć nowego lidera) |
| 4 | **Awaria lidera / klient połączony** | Klient wysyła 20 inkrementów, po 1s DROP lidera — klient musi się odbudować i dokończyć |

Wynik `FAIL` pojawia się gdy:
- Klient nie odpowiada przez określony czas (hung) → `TIMEOUT`
- Czas wykonania przekracza próg maksymalny
- Klient zakończy się błędem

---

## Progi czasowe (FAIL jeśli przekroczone)

| Test | Max czas |
|------|----------|
| Baseline | 5s |
| Awaria followera | 15s |
| Awaria lidera / nowy klient | 20s |
| Awaria lidera / połączony klient | 20s |

---

## Uruchomienie — Docker

### Wymagania
- Docker Desktop
- Zbudowany obraz (patrz niżej)

### Budowanie obrazu
```bash
# Z głównego katalogu projektu
docker compose -f docker/docker-compose.yml build
```

### Testy obydwu transportów
```bash
./benchmark/run_all.sh --docker --transport both
```

### Tylko QUIC
```bash
TRANSPORT=quic docker compose -f docker/docker-compose.yml up -d
./benchmark/run_all.sh --docker --transport quic
```

### Tylko Netty
```bash
TRANSPORT=netty docker compose -f docker/docker-compose.yml up -d
./benchmark/run_all.sh --docker --transport netty
```

> **Uwaga:** Skrypt sam wykrywa lidera z logów — nie musisz sprawdzać ręcznie który węzeł jest liderem.

---

## Uruchomienie — prawdziwe maszyny Linux

### Wymagania
- N maszyn serwerowych z Javą 21+ (nieparzyste N jest lepsze dla Raft)
- 1 maszyna kliencka (lub uruchamiasz skrypt lokalnie)
- Dostęp SSH bez hasła (klucze)
- `sudo iptables` bez hasła dla użytkownika SSH (dodaj do `/etc/sudoers`)

### Konfiguracja

Edytuj `benchmark/config/linux.conf`:
```bash
SSH_USER=student
SERVER_0=192.168.1.10   # węzeł n0
SERVER_1=192.168.1.11   # węzeł n1
SERVER_2=192.168.1.12   # węzeł n2
CLIENT_HOST=            # zostaw puste jeśli klient działa lokalnie
```

### Przygotowanie serwerów (raz)

1. Zbuduj JAR na macOS/lokalnie:
```bash
mvn -pl ratis-examples -am -DskipTests package
```

2. Skopiuj JAR na każdą maszynę:
```bash
scp ratis-examples/target/ratis-examples-*.jar student@192.168.1.10:~/
scp ratis-examples/target/ratis-examples-*.jar student@192.168.1.11:~/
scp ratis-examples/target/ratis-examples-*.jar student@192.168.1.12:~/
```

3. Utwórz plik konfiguracyjny Raft na każdej maszynie (`~/conf.properties`):
```properties
raft.server.address.list=192.168.1.10:10024,192.168.1.11:10124,192.168.1.12:11124
```

4. Uruchom serwery (każdy na swojej maszynie; `RATIS_EXAMPLE_CONF` to **zmienna środowiskowa**,
   nie property `-D` — kod czyta ją przez `JavaUtils.getEnv`):
```bash
# Na maszynie i-tej (peer_index = pozycja adresu w raft.server.address.list, 0-based):
RATIS_EXAMPLE_CONF=~/conf.properties java -cp ratis-examples.jar \
  org.apache.ratis.examples.counter.server.CounterServer <i> --quic
```

5. Uruchom benchmark:
```bash
./benchmark/run_all.sh --linux --transport quic
```

---

## Awaria przez crash vs partycja sieciowa

Skrypty używają `iptables -j DROP` (partycja sieciowa), nie `kill -9` (crash procesu).

| Metoda | Zachowanie | Co mierzymy |
|--------|-----------|-------------|
| `iptables DROP` | Pakiety znikają cicho, brak RST | Czas wykrycia martwego peera przez timeout |
| `kill -9` | OS wysyła TCP RST natychmiast | Tylko czas elekcji Raft |

`iptables DROP` jest bardziej realistyczny — symuluje rzeczywistą partycję sieci (np. awaria switcha, firewall).

---

## Dlaczego QUIC może być szybszy przy awarii lidera

```
TCP (Netty):   requestTimeout = 2s   → klient czeka 2s zanim uzna lidera za martwego
QUIC:          CONNECT_TIMEOUT = 300ms → klient wykrywa martwego peera w 300ms
```

QUIC ma krótszy timeout wykrycia bo QUIC handshake jest szybszy (1 RTT) niż TCP+TLS (3-4 RTT) — można bezpiecznie ustawić krótszy timeout bez ryzyka fałszywych alarmów.

---

## Wyniki — przykładowa tabelka

```
Transport: QUIC
  Baseline (mediana 3 pomiarów)          [PASS] (0.340s)
  Awaria followera / nowy klient         [PASS] (0.317s)
  Awaria lidera / nowy klient            [PASS] (0.798s)
  Awaria lidera / połączony klient       [PASS] (1.200s)

Transport: NETTY
  Baseline (mediana 3 pomiarów)          [PASS] (0.429s)
  Awaria followera / nowy klient         [PASS] (0.515s)
  Awaria lidera / nowy klient            [PASS] (2.100s)
  Awaria lidera / połączony klient       [PASS] (2.300s)
```

Wyniki zapisywane są w `benchmark/results/<timestamp>/`.

---

## Weryfikacja że QUIC jest aktywny (nie TCP)

```bash
# Powinny być widoczne pakiety UDP — dowód na QUIC
docker compose -f docker/docker-compose.yml exec n0 \
  tcpdump -i eth0 -n udp port 10024 -c 20

# Dla Netty — pakiety TCP zamiast UDP
docker compose -f docker/docker-compose.yml exec n0 \
  tcpdump -i eth0 -n tcp port 10024 -c 20
```

---

## Struktura folderów

```
benchmark/
  config/
    docker.conf       ← konfiguracja Docker
    linux.conf        ← konfiguracja maszyn Linux (zmień IP)
  lib.sh              ← funkcje: partition, restore, run_client, find_leader
  run_all.sh          ← główny skrypt (uruchamia wszystkie 4 testy)
  results/            ← wyniki (tworzone automatycznie)
    <timestamp>/
      summary.txt     ← tabela wyników
      output.log      ← pełne wyjście klientów
```
