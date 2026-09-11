# Wariant "heartbeaty z osobnego watku" (HB_THREAD) - rejestr zmian

Data: 2026-09-09/10. Opcja DOMYSLNIE WYLACZONA: bez `--hb-thread` / bez wlasciwosci
`raft.server.log.appender.heartbeat.thread=true` serwer zachowuje sie dokladnie jak dotad,
wiec wszystkie dotychczasowe wyniki (przebiegi 20260828_004326, 20260909_055114_1s) pozostaja
wazne. Wycofanie calosci: usunac nowa klase i cofnac ponizsze fragmenty (`git diff` pokazuje je
w calosci; zaden z plikow nie byl commitowany).

## Po co

Domyslny appender Ratisa (`LogAppenderDefault`) ma jeden watek na followera, ktory wysyla
zadanie (paczke AppendEntries, heartbeat albo fragment InstallSnapshot) i CZEKA na odpowiedz.
Na polaczeniu lider->follower jest wiec zawsze co najwyzej jedno zadanie i heartbeat nigdy nie
leci obok duzej wiadomosci - osobny strumien heartbeatow w module QUIC nie ma czego rozdzielac.
Ten wariant dodaje drugi watek, ktory wysyla heartbeat, gdy do followera nic nie poszlo przez
jeden odstep heartbeatu (polowa minimalnego limitu RPC), i czeka na WLASNA odpowiedz.
Efekt: heartbeat w drodze obok paczki / fragmentu migawki. Ten sam appender pod OBOMA
transportami (TCP i QUIC), zeby jedyna roznica pozostal transport.

## Zmiany (plik -> co -> jak wycofac)

1. `ratis-server/src/main/java/org/apache/ratis/server/leader/LogAppenderWithHeartbeatThread.java`
   NOWY. `public class ... extends LogAppenderDefault`; `run()` startuje watek heartbeatow,
   deleguje do `super.run()`, w `finally` go zatrzymuje. Watek: co odstep heartbeatu, jesli
   `getLastRpcSendTime()` starsze niz odstep -> `newAppendEntriesRequest(callId, true)`,
   `getServerRpc().appendEntries(...)` (blokujaco), z odpowiedzi: `updateLastRpcResponseTime`,
   `NOT_LEADER -> onFollowerTerm`, `onFollowerCommitIndex`, `onAppendEntriesReply`;
   `INCONSISTENCY` ignorowane (indeksy naleza do watku danych); bledy: log DEBUG, bez resetu
   polaczenia. Wypisuje `HBSTAT <followerId> <count> <sumNs>` na stdout co >= 1 s.
   Wycofanie: usunac plik.
2. `ratis-server-api/.../RaftServerConfigKeys.java`, `Log.Appender`: klucz
   `raft.server.log.appender.heartbeat.thread` (`HEARTBEAT_THREAD_KEY`, domyslnie false),
   `heartbeatThread(properties)`, `setHeartbeatThread(properties, boolean)`. Wstawione po
   `setInstallSnapshotEnabled`. Wycofanie: usunac ten blok.
3. `ratis-netty/.../NettyFactory.java` i `ratis-quic/.../QuicFactory.java`: nadpisanie
   `newLogAppender(...)`: gdy wlasciwosc true -> `new LogAppenderWithHeartbeatThread`, inaczej
   `LogAppender.newLogAppenderDefault` (dotychczasowe). Plus 5 importow. Wycofanie: usunac
   metode i importy (`RaftServerConfigKeys`, `leader.FollowerInfo`, `leader.LeaderState`,
   `leader.LogAppender`, `leader.LogAppenderWithHeartbeatThread`).
4. `ratis-server/.../impl/FollowerState.java`: diagnostyka `FGAP` - w `updateLastRpcTime`
   dla `APPEND_START` / `INSTALL_SNAPSHOT_START` / `INSTALL_SNAPSHOT_NOTIFICATION` wypisuje
   `FGAP <id> <ms> <typ>` na stdout, gdy odstep od poprzedniego komunikatu >= prog z
   `-Dratis.fgap.threshold.ms` (bez tej wlasciwosci: nic). Wycofanie: usunac pole
   `FGAP_THRESHOLD_MS` i blok `if` na poczatku metody.
5. `ratis-examples/.../CounterServer.java`: flaga `--hb-thread` (oba transporty) -> nowy
   6-argumentowy konstruktor ustawia `setHeartbeatThread(properties, true)`; 5-argumentowy
   deleguje z `false`; `main`, `startServer`, `printUsage` przekazuja/opisuja flage.
   Wycofanie: cofnac te fragmenty (git diff).
6. `benchmark/lan/run_matrix.sh`: `HB_THREAD=1` -> serwery dostaja ` --hb-thread` (oba
   transporty); `SERVER_JAVA_OPTS` (nowe, domyslnie puste) wstawione do linii startu serwera
   miedzy `$JAVA` a `-cp`; `FGAP_MS=<ms>` dokleja `-Dratis.fgap.threshold.ms`; wpisy w
   `meta.txt` (`hb_thread=`, `fgap_ms=`), w naglowku `wyniki.csv` (linia `# WARIANT: heartbeaty
   z osobnego watku ...`) i w DRYRUN.
7. `benchmark/lan/matrix6.sh`: `HB_THREAD` (export), `FGAP_MS` (export), sufiks `_hb` w
   `RUN_SUFFIX` (wlasna pamiec `~/.matrix6-run_hb`), wypisy w planie, podsumowaniu i naglowku
   kawalka.
8. `benchmark/local/run_local_n.sh`: `HB_THREAD=1` -> ` --hb-thread` dla serwerow; na koncu
   zlicza linie `HBSTAT` w logach serwerow (dowod, ze watek dziala).

## Uzycie

- lokalnie: `N=3 TR=netty HB_THREAD=1 bash benchmark/local/run_local_n.sh`,
  `N=3 TR=quic HB_THREAD=1 bash benchmark/local/run_local_n.sh`
- DCC, cala macierz obu transportow z wariantem: `HB_THREAD=1 FGAP_MS=50 REQ_1MB=200 bash ~/matrix6.sh plan`
  (RUN_ID z sufiksem `_hb`; potrzebny nowy ratis.jar + run_matrix.sh + matrix6.sh na DCC, RUNBOOK 3.3)
- w logach serwerow: `HBSTAT` (RTT heartbeatow z watku, na liderze), `FGAP` (odstepy u followera,
  tylko z FGAP_MS), `HOPSTAT` jak dotad.

## Czego wariant NIE zmienia

Paczki danych i migawki nadal ida po jednej (watek danych bez zmian), wiec przepustowosc,
ogon odczytow i wynik przy 1 MB nie powinny sie zmienic. Zmienia sie tylko to, czy follower
slyszy lidera w czasie duzej wiadomosci - a to widac dopiero pod stratami pakietow
(retransmisja 200 ms w TCP) albo przy migawce do wracajacego followera.

## Stan 2026-09-09 wieczorem

- Build (kopia drzewa poza IDE, sekwencja RUNBOOK 3.1): OK, 223 cele bez bledow; klasa
  `LogAppenderWithHeartbeatThread` w fat jarze, zero klas z "Unresolved compilation" w
  sprawdzanych pakietach. Nowy jar w `ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar`,
  poprzedni zachowany jako `...jar.bak-before-hb` (wycofanie jara = zamiana nazw).
- Smoke test lokalny N=3, `HB_THREAD=1`: TCP i QUIC - serwery wstaly, 40/40 zapisow
  zatwierdzonych, 40/40 odczytow, zero bledow i zerwanych polaczen, zero wyjatkow w logach.
  `HBSTAT` tylko w logu lidera (poprawnie), po ~470 heartbeatow z watku na followera w ~45 s,
  sredni RTT heartbeatu ok. 1 ms.
- NIE zrobione: wdrozenie na DCC (jar + run_matrix.sh + matrix6.sh + run_local_n.sh wg RUNBOOK
  3.3), przebieg macierzy z HB_THREAD=1, scenariusze ze stratami (Docker + netem) i z migawka.
  Nic nie commitowane.

## Dopisane 2026-09-09 wieczorem: os limitu elekcji i liczniki elekcji

9. `CounterServer.java`: flagi `--rpc-timeout=MIN,MAX` (ms; `RaftServerConfigKeys.Rpc.setTimeoutMin/Max`,
   Ratis liczy odstep heartbeatow jako MIN/2) i `--no-prevote` (`LeaderElection.setPreVote(false)`),
   przekazywane przez nowy 7-argumentowy konstruktor z `Consumer<RaftProperties>` (6-argumentowy
   deleguje z `null`). Walidacja: 0 < MIN <= MAX. Wycofanie: cofnac fragmenty (git diff).
10. `run_matrix.sh`: `RPC_TIMEOUT=MIN,MAX`, `NO_PREVOTE=1` -> flagi serwerow (oba transporty);
    `snapshot_servers` liczy dodatkowo przejscia "FOLLOWER to CANDIDATE" (4 pola zamiast 3),
    `finish_point` zapisuje `CANDIDATES=` do `point_*.env`; wpisy w meta.txt, naglowku wyniki.csv
    i DRYRUN.
11. `scal.sh`: NOWA OSTATNIA kolumna `candidate_attempts` w `wyniki.csv` (naglowek + wiersz).
    Uwaga: pliki wyniki.csv tworzone od teraz maja 37 kolumn; stare maja 36. Skrypt do Excela
    (`.claude/skills/wyniki-do-excela`) dopasowuje kolumny po nazwie/pozycji - sprawdzic przy
    pierwszym wklejaniu.
12. `matrix6.sh`: `RPC_TIMEOUT`, `NO_PREVOTE` (export), sufiksy RUN_ID `_t<MIN>` i `_np`, wypisy.
13. `run_local_n.sh`: te same zmienne -> flagi serwerow; na koncu zlicza przejscia rol z logow.

Semantyka licznikow (oba z logow serwerow, delta na punkt, suma po wszystkich serwerach):
- `elections` = przejscia "-> LEADER" (nowy lider wybrany),
- `candidate_attempts` = przejscia "FOLLOWER -> CANDIDATE" (follower przekroczyl limit; z pre-vote
  zwykle konczy sie odmowa i powrotem do FOLLOWER, bez pre-vote podnosi termin i obala lidera).

Stan po dopisaniu flag (2026-09-09, 21:07): jar przebudowany (BUILD SUCCESS, flagi w klasie),
smoke test lokalny N=3 z `HB_THREAD=1 RPC_TIMEOUT=100,200 NO_PREVOTE=1` dla TCP i QUIC: serwery
wstaly, 40/40 zapisow i odczytow, zero bledow, HBSTAT u lidera dla obu followerow. Nowy jar w
`ratis-examples/target/`, poprzedni nadal w `...jar.bak-before-hb`. NIE wdrozone na DCC.
UWAGA: nie nadpisywac run_matrix.sh / matrix6.sh / scal.sh na DCC w trakcie trwajacego przebiegu
(bash czyta skrypt przyrostowo) - wgrac dopiero po zakonczeniu.

14. `benchmark/lan/pilot_hb.sh` (NOWY): pilot na ~15 min w rezerwacji 30 min. Trzy warianty po
    jednym punkcie 1 MB / conn B / uklad "6 6 6 6 6" (30 workerow), REQ=60 zadan na klienta,
    wszystkie z HB_THREAD=1 i RPC_TIMEOUT=100,200: tcp, quic (5 strumieni), quic1s (1 strumien).
    Kazdy wariant = osobne wywolanie run_matrix.sh (RUN_ID pilot_<ts>_<wariant>), po nim zbior
    linii FGAP/HBSTAT z logow serwerow do ~/raft-results/<RUN_ID>/fgap/. Na koncu tabela
    (zapisy/s, p99, RTT AE, elections, candidate_attempts) i rozklad FGAP na wariant (awk, bez
    pythona). Zmienne: REQ, LAYOUT, RPC_TIMEOUT, NO_PREVOTE, HB_THREAD, VARIANTS, FGAP_MS.
    Wymaga na DCC: ~/ratis.jar (nowy), ~/run_matrix.sh, ~/scal.sh, ~/log4j.properties, ~/pilot_hb.sh.
15. `benchmark/lan/fgap_stats.py` (NOWY): to samo podsumowanie FGAP/HBSTAT w Pythonie, do uzycia
    lokalnie na sciagnietych plikach fgap/*.txt (nazwa pliku zaczyna sie od quic_/tcp_).
    Uzupelnienie 14: `RAM_LOG=1` w pilocie = ten sam pilot bez zapisu na dysk (tmpfs jak w wariancie
    kontrolnym; pilot ustawia RAM_LOG_ALLOW_1MB=1, log punktu ok. (REQ+WARMUP) x workerow MB);
    sciezka logow serwerow do zbioru FGAP/HBSTAT czytana z meta.txt (storage_root=), pilot nie
    eksportuje STORAGE_ROOT (blad z pierwszej wersji, ktory nadpisywalby tmpfs sciezka /data).

16. `run_matrix.sh`: `READTPUT=1` - pomiar "sama przepustowosc danych" po punktach kazdego bloku, na
    zywym klastrze: sami czytelnicy (RaftBench `--mode scaling --read-ratio 1.0`), stale read z
    followerow (READTPUT_FROM), odpowiedz = READTPUT_PAYLOAD (1MB) z pamieci followera, bez
    konsensusu i bez dysku. Jeden proces na wezel kliencki, READTPUT_CLIENTS (6:6:1 = 30 czytelnikow
    lacznie), READTPUT_REQ odczytow na czytelnika. Scalony wiersz na blok w `$RESULTS/readtput.csv`
    (readers_total, read_tput_req_s, read_MB_s, p50 srednia, p99 max, reads_ok/failed), surowe CSV
    w readtput_<tr>_n<N>_<wezel>.csv, wpis w meta.txt i DRYRUN. Funkcja `run_readtput` przed
    `wait_clients`; wywolanie w petli blokow przed `dump_logs`. Scalenie przetestowane na
    syntetycznych CSV. Wycofanie: usunac blok zmiennych READTPUT*, funkcje i jedna linie w petli.

17. `CounterServer.java`: wlasciwosc systemowa `-Dratis.log.write.buffer=<rozmiar>` ustawia
    `raft.server.log.write.buffer.size` (domyslnie 8MB); potrzebna, gdy `-Dratis.appender.buffer`
    przekracza 8 MB, bo Ratis wymaga write.buffer >= appender.buffer + 8 B (blad z pilota bez dysku,
    2026-09-09 22:55). Uzycie: SERVER_JAVA_OPTS="-Dratis.appender.buffer=16MB -Dratis.log.write.buffer=32MB".
    Obejscie bez przebudowy: -Dratis.appender.buffer=8388600 (tuz pod 8 MB) z RPC_TIMEOUT=60,120.

18. `run_matrix.sh` `snapshot_servers`: liczniki elekcji/prob liczone z DWOCH loggerow i brane
    maksimum: RaftServerImpl ("changes role ... to LEADER" / "FOLLOWER to CANDIDATE") oraz
    LeaderElection ("ELECTION round N: result PASSED" / "PRE_VOTE round 0: submit vote requests",
    a bez pre-vote "ELECTION round 0: submit vote requests"). Powod: plik ~/log4j.properties na DCC
    (z 2026-09-09 05:51) ma INFO tylko dla LeaderElection, wiec dotychczasowy licznik z
    RaftServerImpl dawal zawsze 0 (wykryte w pilocie 2026-09-09 ~23:05: 'to LEADER' = 0 mimo
    wybranego lidera). Do wgrania na DCC razem z aktualnym benchmark/lan/log4j.properties.
    UWAGA do pracy: kolumna elections we WSZYSTKICH dotychczasowych przebiegach mogla byc martwa -
    "zero elekcji" trzeba potwierdzic z zachowanych logow serwerow liniami LeaderElection
    ("submit vote requests at term N" z N > 1).

19. `benchmark/lan/log4j.properties`: linie "changes role ..." pisze `RaftServer.Division.LOG`
    (logger `org.apache.ratis.server.RaftServer$Division`, RaftServer.java:63), NIE logger
    `...impl.RaftServerImpl` - stary wpis nigdy nie dzialal, wiec kolumna `elections` (grep
    "changes role ... to LEADER") byla 0 we WSZYSTKICH przebiegach, takze w macierzy glownej.
    Dodano `RaftServer$Division=INFO` i `RaftServer=INFO`. Sprawdzenie z zachowanych logow
    (LeaderElection, "submit vote requests at term N", N>=2): macierz glowna 130 linii w logach
    blokow 1 MB, _1s 59, _hb 9 -> "zero elekcji w 72 punktach" w pracy jest NIEPOTWIERDZONE,
    analiza w toku (2026-09-09 23:15). Plik wgrany na DCC przez mv.

## Wyniki pilotow (2026-09-09/10, wezly dcc-1,7,9,10,11 + klienci 12-16, tmpfs, paczka 8388600 B,
## HB_THREAD=1, 30 workerow x 1 MB, REQ=25)

| limit elekcji | wariant | zatwierdzone | proby elekcji | zmiany lidera | uwagi |
|---|---|---|---|---|---|
| 60/120  | tcp     | 0/750 (600 s) | 3590 (z logow) | 62 | kaskada elekcji |
| 60/120  | quic    | 750/750, 19.8/s | 0 po starcie | 0 | FGAP max 71 ms |
| 60/120  | quic1s  | 0/750 (600 s) | 5629 (z logow) | 23 | jak TCP |
| 100/200 | tcp     | 0/750 (605 s) | 861 (CSV)     | 22 | AE RTT 71 ms |
| 100/200 | quic    | 750/750, 18.8/s | 0 (CSV)     | 0  | read p99 109 ms, AE 181 ms |
| 100/200 | quic1s  | 0/750 (604 s) | 641 (CSV)     | 9  | jak TCP |

Roznica quic vs quic1s = wylacznie uklad strumieni (ta sama biblioteka, nadawca, wezly, brak dysku).
| 150/300 | tcp     | 0/750 (timeout) | 166 (CSV) | 5  | FGAP p90 194, max 395; 29 % > 150 ms; HBSTAT 82 (RTT 9 ms) |
| 150/300 | quic    | 750/750, 19.7/s | 0 | 0 | FGAP max 141 ms; HBSTAT 2257 (RTT 6.2 ms) |
| 150/300 | quic1s  | 0/750 (timeout) | 642 | 10 | FGAP p99 329, max 549; HBSTAT 201 (RTT 87 ms = HOL heartbeatu za paczka) |
(pilot_20260910_001236, domyslne limity Ratisa)
| 150/300, paczka 4 MB | tcp    | 750/750, 24.7/s | 0 | 0 | FGAP p99 135, max 176; HBSTAT RTT 35.7 ms (= czas transmisji 4 MB) |
| 150/300, paczka 4 MB | quic   | 750/750, 18.7/s | 0 | 0 | FGAP p99 89, max 156; HBSTAT RTT 6.0 ms |
| 150/300, paczka 4 MB | quic1s | 750/750, 20.2/s | 5 | 0 | FGAP p99 211, max 332; HBSTAT RTT 50.6 ms |
(pilot_20260910_002645)
| 150/300, paczka 6 MB | tcp    | 750/750, 25.4/s | 4 | 0 | FGAP p99 217, max 262, 18 % > 150 ms; HBSTAT RTT 57 ms (= 6 MB wire) |
| 150/300, paczka 6 MB | quic   | 750/750, 19.5/s | 0 | 0 | FGAP p99 98, max 146; RTT 6.6 ms |
| 150/300, paczka 6 MB | quic1s | 750/750, 16.5/s, read p99 1370 | 89 | 11 | FGAP p99 303, max 356; RTT 99 ms |
(pilot_20260910_005353)
| 150/300, paczka 7 MB | tcp    | 750/750, 24.6/s | 17 | 1 | FGAP p99 276, max 319, 21 % > 150 ms; HBSTAT RTT 83 ms |
| 150/300, paczka 7 MB | quic   | 750/750, 19.9/s | 0 | 0 | FGAP p99 94, max 158; RTT 6.1 ms |
| 150/300, paczka 7 MB | quic1s | 0/750 (300 s)   | 417 | 5 | zapasc; RTT 129 ms |
(pilot_20260910_010758, uruchomiony przez autora)
| 120/240, paczka 7 MB, REQ=50 | tcp | 750/1500?, 6.0/s | 163 | 6 | "spowolniony, dziala"; UWAGA REQ=50 = 1.65 GB logu na tmpfs 4 GB |
| 120/240, paczka 7 MB, REQ=50 | quic | 0 (stuck follower, brak miejsca na tmpfs?) | 0 | 0 | NIEWAZNY |
| 120/240, paczka 7 MB, REQ=25 | quic | 750/750, 19.3/s | 0 | 0 | FGAP max 133; RTT 5.6 ms (pilot_20260910_014238) |
Regula: pod RAM_LOG na wezlach 4 GB REQ<=25 (log punktu <= ~0.9 GB).
| 120/240, paczka 7 MB, REQ=25 | tcp | 750/750, 14.8/s, p99 zap 10.7 s | 94 | 7 | FGAP p99 263, max 5017 ms (pilot_20260910_014518) |
| 120/240, paczka 7 MB, REQ=25 | quic1s | 0/750 (300 s) | 482 | 8 | zapasc; FGAP p99 228, max 398 (pilot_20260910_014746) |
| DYSK, 150/300, paczka 4 MB, REQ=40 | tcp | 13.5/s | 0 | 0 | FGAP p99 111, max 243; HBSTAT RTT 108 ms (wire + fsync) |
| DYSK, 150/300, paczka 4 MB, REQ=40 | quic | 11.0/s | 0 | 0 | FGAP p99 87, max 132; RTT 3.0 ms |
| DYSK, 150/300, paczka 4 MB, REQ=40 | quic1s | 11.4/s | 1 | 0 | FGAP p99 170, max 273; RTT 99 ms (pilot_20260910_015543) |
| DYSK, 150/300, paczka 8 MB, REQ=40 | tcp | 14.5/s | 2 | 0 | FGAP p99 218, max 295 (8.9 % > 150); HBSTAT RTT 150 ms |
| DYSK, 150/300, paczka 8 MB, REQ=40 | quic | 11.9/s | 0 | 0 | FGAP p99 87, max 145; RTT 3.5 ms |
| DYSK, 150/300, paczka 8 MB, REQ=40 | quic1s | 0/1200 (300 s) | 430 | 12 | zapasc; FGAP p99 301, max 432; RTT 134 ms (pilot_20260910_020439) |
Wniosek: czas fsync jest chroniony przez Ratisa (zerowanie limitu przy APPEND_START), wiec dysk nie
zwieksza ekspozycji followera; TCP pada przy 8 MB na tmpfs, na dysku jeszcze nie; QUIC z jednym
strumieniem pada w obu przypadkach, QUIC z pieciu nigdy.

## Zbiorczy plik wyników pilotów

Wszystkie wyniki pilotów (tabele, elekcje z macierzy głównej, wnioski, komendy) spisane 10.09.2026 w
`/Users/tomek/projekt/praca_tresc/piloty_elekcje_2026-09-10.md`.

## 20. Zapis opcji serwera w wynikach (2026-09-10 03:20)

Problem: pilot_20260910_030242 (dysk, 150/300) mial byc z paczka 12 MB, ale wyniki (RTT heartbeatu
152 ms, RTT AE 244 ms, 15,0 zapisow/s) sa identyczne z pilotem 8 MB, a NIGDZIE nie bylo zapisane,
z jakim SERVER_JAVA_OPTS wystartowaly serwery (meta.txt mial tylko APPENDER_BUFFER, czyli stary
mechanizm przez plik conf, nieuzywany w pilotach). Zmiana:
- `benchmark/lan/run_matrix.sh`: meta.txt dostaje linie `server_java_opts=...`; naglowek wyniki.csv
  dostaje linie `# OPCJE SERWERA (SERVER_JAVA_OPTS, ...)`, gdy zmienna niepusta.
- `benchmark/lan/pilot_hb.sh`: oba naglowki (start i podsumowanie) drukuja `opcje serwera (SERVER_JAVA_OPTS)`.
Wycofanie: usunac te trzy echo. Wymaga ponownego scp obu skryptow na klaster (robi uzytkownik).

## 21. Skrypt szukajacy punktu na dysku (2026-09-10 03:55)

`benchmark/lan/szukaj_dysk8.sh` (NOWY, kopiowany do ~ na klastrze obok pilot_hb.sh): dysk, paczka
8 MB (8388600), REQ=40, watek heartbeatow, pre-vote. Proby TCP-only od MIN=120 ms (MAX=2*MIN),
polowienie przedzialu miedzy znanymi 100 (zapasc) i 150 (0 zmian): zapasc -> luzniej, 0 zmian ->
ostrzej, maks. PROBES=4. Punkt "znaleziony" = TCP zatwierdza zapisy I ma >=1 zmiane lidera. W nim
QUIC + QUIC jednostrumieniowy, potem REPS=2 pelne powtorzenia trojki. Na koncu tabela wszystkich
wierszy wybranego limitu. Katalogi ~/raft-results/szukaj_<ts>_t<MIN>[_rN]_<wariant>.
Przetestowany lokalnie na atrapie pilot_hb.sh (3 scenariusze). Wycofanie: usunac plik.
