<!--
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License. See accompanying LICENSE file.
-->

# Raft over QUIC: fork Apache Ratis z transportem QUIC

To repozytorium jest kopią rozwojową [Apache Ratis](https://ratis.apache.org/) (3.3.0-SNAPSHOT)
przygotowaną na potrzeby pracy magisterskiej na Politechnice Poznańskiej. Dodaje do biblioteki
wymienny transport RPC oparty na protokole QUIC i porównuje go ilościowo z transportem
referencyjnym TCP z TLS 1.3 na klastrze Raft. Poniżej tej sekcji znajduje się niezmienione
README projektu Apache Ratis.

**Zmiany względem Apache Ratis:**

- `ratis-quic`: nowy moduł transportu QUIC (`QuicFactory`, `QuicRpcService`, `QuicRpcProxy`,
  `QuicClientRpc`) na bibliotece netty-incubator-codec-quic (quiche + BoringSSL). Połączenie
  serwer-serwer prowadzi pięć trwałych strumieni, po jednym na typ komunikatu, więc heartbeat
  nie czeka w kolejce za replikacją logów; opcjonalny układ jednostrumieniowy
  (`raft.quic.server.single-stream`) służy jako punkt odniesienia.
- `ratis-netty`: TLS 1.3 na ścieżce RPC transportu referencyjnego oraz domyślnie wyłączona opcja
  osobnego wątku heartbeatów (`--hb-thread`, rejestr w [HB-THREAD-CHANGES.md](HB-THREAD-CHANGES.md)).
- `ratis-server`: diagnostyka opóźnień AppendEntries po stronie lidera (HOPSTAT) i przerw między
  heartbeatami po stronie followera (FGAP).
- `ratis-examples`: `CounterServer` z flagami `--quic`, `--single-stream`, `--hb-thread`,
  `--rpc-timeout`, `--no-prevote`; sonda PING/PONG w `CounterStateMachine`; narzędzie pomiarowe
  `RaftBench` (zapis przez konsensus + odczyt z followera w pętli zamkniętej).
- `benchmark/`: skrypty macierzy pomiarowej na klastrze SLURM (`run_matrix.sh`, `matrix6.sh`,
  `scal.sh`), piloty stabilności przywództwa i wyniki (`benchmark/results/`).
- `docker/`: klaster w kontenerach do testów funkcjonalnych obu transportów.

Opis eksperymentu, metryk i procedury pomiarowej: [benchmark/README.md](benchmark/README.md).
Opis implementacji modułu QUIC: [QUIC_IMPLEMENTATION.md](QUIC_IMPLEMENTATION.md).
Stan kodu odpowiadający wersji pracy oznaczono tagiem `praca-mgr-2026-09`.

---

# Apache Ratis
*[Apache Ratis]* is a Java library that implements the Raft protocol [1],
where an extended version of the Raft paper is available at <https://raft.github.io/raft.pdf>.
The paper introduces Raft and states its motivations in following words:

> Raft is a consensus algorithm for managing a replicated log.
> It produces a result equivalent to (multi-)Paxos, and it is as efficient as Paxos,
> but its structure is different from Paxos; this makes Raft more understandable than Paxos
> and also provides a better foundation for building practical systems.

Ratis aims to make Raft available as a java library that can be used by any system that needs to use a replicated log.
It provides pluggability for state machine implementations to manage replicated states.
It also provides pluggability for Raft log, rpc implementations and metric implementations to make it easy for integration with other projects.
Another important goal is to support high throughput data ingest so that it can be used for more general data replication use cases.

* To build the artifacts, see [BUILDING.md](BUILDING.md).
* To run the examples, see [ratis-examples/README.md](ratis-examples/README.md).

## Reference
1. Diego Ongaro and John Ousterhout,
_[In Search of an Understandable Consensus Algorithm][Ongaro2014]_,
2014 USENIX Annual Technical Conference (USENIX ATC 14) (Philadelphia, PA), USENIX Association, 2014, pp. 305-319.

[Ongaro2014]: https://www.usenix.org/conference/atc14/technical-sessions/presentation/ongaro

[Apache Ratis]: https://ratis.apache.org/
