Masz kilka poziomów testowania:

1. Podstawowy test funkcjonalny
Uruchom 3 serwery + klient i sprawdź czy wynik się zgadza:


java -cp ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar org.apache.ratis.examples.counter.client.CounterClient 10 IO --quic
Oczekiwany wynik: Current counter value: 10

2. Test odporności na awarie (fault tolerance)
Zatrzymaj jednego z followerów w trakcie działania — klaster powinien dalej działać (Raft toleruje utratę minority):


# zabij serwer 2
pkill -f "CounterServer 2"
# wyślij komendy — powinno działać
java -cp ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar org.apache.ratis.examples.counter.client.CounterClient 10 IO --quic
3. Test wydajnościowy (ASYNC vs IO)

# wiele żądań asynchronicznie
java -cp ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar org.apache.ratis.examples.counter.client.CounterClient 1000 ASYNC --quic
Klient wypisze throughput w op/s.

4. Porównanie QUIC vs Netty/TCP
Uruchom ten sam test bez --quic i porównaj throughput:


# Netty/TCP
java -cp ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar org.apache.ratis.examples.counter.client.CounterClient 1000 ASYNC

# QUIC
java -cp ratis-examples/target/ratis-examples-3.3.0-SNAPSHOT.jar org.apache.ratis.examples.counter.client.CounterClient 1000 ASYNC --quic
5. Sprawdzenie że naprawdę używa QUIC
W logach serwera powinieneś widzieć:


raft.rpc.type = QUIC (custom)
i


QUIC server started on /0.0.0.0:10024
To potwierdza że transport jest QUIC a nie TCP.

Problem 1 — readIndexAsync rzuca wyjątek na followerze i jest gdzieś łapany cicho
Problem 2 — po restarcie serwera QuicRpcProxy nie odbudowuje połączenia (brak reconnect logic)