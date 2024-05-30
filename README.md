# IPK Projekt 2 - ZETA: Packet sniffer
## Úvod
Cieľom bolo navrhnúť a implementovať sieťový analyzátor, ktorý bude schopný zachytávať a filtrovať pakety na špecifickom sieťovom rozhraní.

*Packet sniffer* je aplikácia, ktorá umožňuje sledovať a analyzovať sieťovú komunikáciu. Tento proces zahŕňa zachytávanie a zobrazovanie sieťových paketov, ktoré prechádzajú cez sieťové rozhranie, ktoré je na hostiteľskom počítači nainštalované. Po zachytení týchto paketov môže *sniffer* analyzovať ich obsah a zistiť rôzne informácie o sieťovej komunikácii, ako sú napríklad zdrojová a cieľová IP adresa, zdrojový a cieľový port, a obsah dát.

Implementácia packet snifferu v jazyku C zahŕňa použitie knižnice `pcap`, ktorá poskytuje nízkoúrovňové rozhranie pre zachytávanie sieťových paketov. Pomocou tejto knižnice môžete otvoriť sieťové rozhranie a zachytiť všetky pakety, ktoré cez ne prechádzajú. Následne môžete tieto pakety analyzovať a zobrazovať ich obsah pomocou rôznych techník, ako sú napríklad výpis hexadecimálneho obsahu paketu alebo analýza hlavičky paketu.

Protokol je v informatike a telekomunikáciách súbor pravidiel a postupov, ktoré určujú, ako majú komunikovať dve (alebo viac) zariadenia. Je to spôsob, ako si zariadenia vymieňajú informácie, ktoré majú byť spracované a zrozumiteľné pre obe strany. Protokoly sú bežne používané v sieťach a internete, aby zabezpečili spoľahlivú a efektívnu komunikáciu medzi rôznymi zariadeniami.

Protokoly sú často vrstvené a organizované do hierarchií, ktoré umožňujú efektívne spracovanie dát na rôznych úrovniach. Napríklad v TCP/IP protokolovom stacku, ktorý sa používa na internete, sú protokoly organizované do štyroch vrstiev: aplikačnej, transportnej, sieťovej a linkovej vrstvy.

*Packet sniffer* sa zameriava na zachytenie a analýzu paketov, ktoré sú prenášané cez sieťovú vrstvu. Vďaka tomu je možné sledovať a analyzovať komunikáciu medzi zariadeniami a získať cenné informácie o prenášaných dátach a sieťovom prevádzke. Protokoly, na ktoré sa zameriava, sú zodpovedné za prenos dát cez sieť, ako napríklad TCP, UDP, IP, ICMP, ARP a podobne.

Pre jednoduchšie pochopenie výstupu *packet snifferu* si dovolím vysvetliť ešte niekoľko termínov:
1) **MAC adresa** (*Media Access Control*) je jedinečná adresa priradená sieťovej karte (*network interface card* - NIC). Každá sieťová karta má svoju vlastnú MAC adresu, ktorá sa používa na identifikáciu konkrétnej karty v sieti. MAC adresa pozostáva z 6 oktetov (48 bitov) a zapisuje sa v šestnástkovej sústave.
2) **IP adresa** (*Internet Protocol*) je jedinečná adresa priradená zariadeniu v sieti, ktorá umožňuje komunikáciu s inými zariadeniami v sieti. IP adresa sa skladá z čísel, ktoré sú rozdelené bodkami a pozostávajú z 4 oktetov (32 bitov). IP adresy sa používajú na identifikáciu zariadení v sieti a umožňujú doručovanie paketov od jedného zariadenia k druhému.
3) **Port** je číselné označenie, ktoré umožňuje aplikáciám identifikovať a smerovať dáta na konkrétnu službu alebo aplikáciu v sieti. V rámci jedného zariadenia môže byť otvorených niekoľko portov, každý pre inú aplikáciu alebo službu. Portové čísla sa pohybujú od 0 do 65535.
### Užívateľská prívetivosť
Pri implementácii *packet snifferu* som sa snažil byť čo najprívetivejší k užívateľom a preto som do programu pridal funkcionalitu pre výpis nápovedy s použitím argumentu `-h`. Táto funkcia užívateľom poskytuje prehľad o tom, ako sa program používa a aké argumenty sú k dispozícii, čím uľahčuje prácu s programom a minimalizuje riziko nesprávneho použitia. Vďaka tomu majú užívatelia jasnú predstavu o tom, aké možnosti majú a ako ich môžu využiť, a tým sa zvyšuje pravdepodobnosť, že budú schopní program úspešne využiť 

## Spustenie
1) Naklonujte si tento repozitár, poprípade extrahujte súbor:
```
git clone https://github.com/astrigac/Packet-sniffer.git
```
2) Preložte súbor:    
```
make 
```
3) Spustite program:
```
./sniffer -h [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}
``` 
&nbsp;&nbsp;&nbsp;&nbsp; kde:

* `-h` vypíše užívateľskú nápovedu, používa sa bez žiadnych ďalších argumentov
* `-i eth0` (len jedno rozhranie na pričuchnutie) alebo `--interface`. Ak tento parameter nie je špecifikovaný (a tiež akékoľvek iné parametre), alebo ak je zadaný iba `-i/--interface` bez hodnoty (a akékoľvek ďalšie parametre nie sú špecifikované), vytlačí sa zoznam aktívnych rozhraní.
* `-t` alebo `--tcp` zobrazí segmenty TCP a je voliteľne doplnené funkciou `-p`.
* `-u` alebo `--udp` zobrazí datagramy UDP a je voliteľne doplnená funkciou `-p`.
* `-p port` rozširuje predchádzajúce dva parametre o filtrovanie TCP/UDP na základe čísla `port`.
* `--icmp4` zobrazí iba pakety ICMPv4.
* `--icmp6` zobrazí iba žiadosť/odpoveď o odozve ICMPv6.
* `--arp` zobrazí len snímky ARP.
* `--ndp` zobrazí iba pakety ICMPv6 NDP.
* `--igmp` zobrazí iba pakety IGMP.
* `--mld` zobrazí iba pakety MLD.
* Pokiaľ protokoly nie sú výslovne uvedené, na tlač sa berie do úvahy všetok obsah (t. j. všetky pakety bez ohľadu na protokol).
* `-n num` (určuje počet paketov, ktoré sa majú zobraziť, t. j. „čas“ spustenia programu)
* Všetky argumenty môžu byť v ľubovoľnom poradí.

## Popis jednotlivých funkcií
- `void  printHelp()` - Funkcia pre tlač užívateľskej nápovedy.
- `void  printError(ErrorCode  c)` - Funkcia pre tlač rôznych druhov chybových hlášok na základe vstupného argumentu a kombinácie štruktúr `const  char*  errorDesc[]` a `typedef enum ErrorCode`.
- `void  printActiveInterfaces()` - Funkcia pre tlač všetkých aktívnych rozhraní na aktuálnom stroji.
- `void checkInterface(char  name[])` - Funkcia na kontrolu, či rozhranie na aktuálnom počítači existuje z dôvodu, aby užívateľ nemohol zadať rozhranie ktoré neexistuje.
- `void  checkPort(int  port)` - Funkcia na kontrolu parametrov portu, aby užívateľ nemohol zadať číslo portu ktoré neexistuje.
- `void  checkDigitOptarg(char  *optarg)` - Funkcia na kontrolu či všetky znaky v reťazci sú čísla. 
- `void  repetetiveArgumentPrevent(int  *arg)` - Funkcia ktorá pozoruje že užívateľ nepoužil istý argument viackrát. 
- `void  parseArguments(int  argc,  char  *argv[],  char  interface[],  int  *tcp,  int  *udp,  int  *port,  int  *arp,  int  *icmp4,  int  *icmp6,  int  *ndp,  int  *igmp,  int  *mld,  int  *num)` - Funkcia pre analýzu argumentov. Funkcia nastavuje príznaky `int  *tcp,  int  *udp,  int  *port,  int  *arp,  int  *icmp4,  int  *icmp6,  int  *ndp,  int  *igmp,  int  *mld,  int  *num` na základe `char  *argv[]`. Zároveň kontroluje že program bol zavolaný správne. Pre spracovanie argumentov táto funkcia používa štruktúru `struct  option  long_options[]` v kombinácií s funkciou `getopt_long()`.
- `void  printOrIfNeeded(bool  *not_first,  char  filter_exp[],  int  *offset)` - Pomocná funkcia používaná na vkladanie „or“ medzi jednotlivé filtre. Táto funkcia sa hlavne využíva v nasledujúcej funkcií.
- `void  constructFilter(char  filter_exp[],  int  tcp,  int  udp,  int  port,  int  arp,  int  icmp4,  int  icmp6,  int  ndp,  int  igmp,  int  mld)` - Funkcia používaná na konštrukciu filtrov rôznych druhov. Výsledný filter ukladá do reťazca `char  filter_exp[]`.  Práve knižnica `pcap` umožňuje použitie takýchto filtrov, a to na zachytávanie a analýzu sieťového prevádzky. Filter v `pcap` slúži na definovanie podmienok, ktoré musí sieťový paket spĺňať, aby bol zachytený a spracovaný.
- `void  timevalToString(struct  timeval  time,  char  result[])` - Funkcia používaná na prevod časovej hodnoty vo formáte RFC3339 na vytlačiteľný reťazec.
- `void  getMacAddress(char  *mac_buffer,  const  u_char  *mac_bytes)` - Funkcia na získanie mac adresy v správnom formáte z reťazca.
- `void  printPacketData(const  u_char  *data,  bpf_u_int32  length)` - Hexdump funkcia pre výpis obsahu paketu v správnom formáte.
- `void  packetHandler(u_char  *args,  const  struct  pcap_pkthdr  *header,  const  u_char  *packet)` - Funkcia callback, ktorá sa používa v knižnici `pcap` na spracovanie každého zachyteného paketu v reálnom čase. Táto funkcia sa volá pre každý paket zachytený v sieti. Jej výsledok je výpis obsahu paketu obsahujúci informácie ako zdrojová a cieľová MAC adresa, zdrojová a cieľová IP adresa, čas, dĺžka rámca a mnoho ďalších.
## Testovanie
### Testovacie prostredie
Operačný systém: *nixOS*
Aplikácie použité počas testovania: *Terminal* a *Wireshark*
### Testy
#### Kontrola vstupných argumentov
Testy boli vykonané aby sa zabránilo užívateľovi spustenie programu s neplatnými argumentami čo by predchádzalo nesprávnej funkcionalite programu.
##### Neplatný argument
- Spustenie: 
```
sudo ./sniffer -i enp0s3 --icmp
```
- Očakávaný výstup:
``` 
(Chybová hláška)
```
- Skutočný výstup:
``` 
Wrong function arguments
For more info, use ./sniffer -h
```
##### Neexistujúce rozhranie
- Spustenie:
``` 
sudo ./sniffer -i enp0s
```
- Očakávaný výstup:
``` 
(Chybová hláška)
```
- Skutočný výstup:
``` 
Interface does not exist
For more info, use ./sniffer -h
```
##### Negatívny počet paketov
- Spustenie:
``` 
sudo ./sniffer -i enp0s3 --tcp -n -3
```
- Očakávaný výstup:
``` 
(Chybová hláška)
```
- Skutočný výstup: 
```
Digit argument in wrong format
For more info, use ./sniffer -h
```
#### Výpis aktívnych rozhraní
Testy boli vykonané pre kontrolu správnej funkčnosti tejto funkcionality. Táto funkcionalita je veľmi potrebná pretože uľahčuje užívateľovi prístup ku zoznamu zariadení ktoré môže sledovať. 
##### Spustenie programu bez argumentov
- Spustenie:
``` 
sudo ./sniffer
```
- Očakávaný výstup:
``` 
List of active interfaces:
(Zoznam aktívnych rozhraní)
```
- Skutočný výstup: 
```
List of active interfaces:
enp0s3
any
lo

```
##### Spustenie programu iba s argumentom --interface
- Spustenie:
``` 
sudo ./sniffer --interface
```
- Očakávaný výstup:
``` 
List of active interfaces:
(Zoznam aktívnych rozhraní)
```
- Skutočný výstup: 
```
List of active interfaces:
enp0s3
any
lo

```
#### Správna konštrukcia a preloženie filtru
Test bol vykonaný z dôvodu kontroly že filter ktorý program vytvorí je správny, preložiteľný a užitočný.
- Spustenie:
``` 
sudo ./sniffer -i enp0s3 -p 35
```
- Očakávaný výstup:
``` 
FILTER:
 (Reťazec s filtrom)
Filter succesfully compiled
```
- Skutočný výstup: 
```
FILTER:
 tcp port 35 or udp port 35 or arp or icmp or (icmp6 and (icmp6[0] = 128 or icmp6[0] = 129)) or (icmp6 and icmp6[0] = 135) or (icmp6 and icmp6[0] = 136) or igmp or (icmp6 and (icmp6[0] = 130 or icmp6[0] = 131))
Filter succesfully compiled

```
#### Správna funkčnosť
Testy boli vykonané pre kontrolu že program skutočne funguje a že jeho výstup súhlasí so zadaním.
##### Použitie filtru --tcp na rozhraní enp0s3
- Spustenie:
``` 
sudo ./sniffer -i enp0s3 --tcp
```
- Referenčný paket v aplikácií Wireshark: ![tcp1](https://user-images.githubusercontent.com/101597718/232592497-7f9ff96a-40cb-4fd4-bbf7-01668d0bbefa.png)
![tcp2](https://user-images.githubusercontent.com/101597718/232592579-2345c40c-137d-463b-b367-fac2ea8e8c79.png)

- Skutočný výstup: 
```
timestamp: 2023-04-17T19:26:12.108+00:00
src MAC: 08:00:27:56:aa:92
dst MAC: 52:54:00:12:35:02
frame length: 84 bytes
src IP: 10.0.2.15
dst IP: 34.117.65.55
src port: 59570
dst port: 443
0x0000:  52 54 00 12  35 02 08 00  27 56 aa 92  08 00 45 00   RT..5... 'V....E.
0x0010:  00 46 5b 3a  40 00 40 06  6f bd 0a 00  02 0f 22 75   .F[:@.@. o....."u
0x0020:  41 37 e8 b2  01 bb 26 c8  f8 67 35 f0  9e 6a 50 18   A7....&. .g5..jP.
0x0030:  fa 16 6f f3  00 00 17 03  03 00 19 f2  61 e6 9f b3   ..o..... ....a...
0x0040:  d8 44 4c fa  83 02 d0 c0  c5 cd 46 5f  92 b1 2b 0d   .DL..... ..F_..+.
0x0050:  49 5d ab c9                                          I]..

```
##### Použitie filtru --arp na rozhraní enp0s3
- Spustenie:
``` 
sudo ./sniffer -i enp0s3 --arp
```
- Referenčný paket v aplikácií Wireshark: ![arp1](https://user-images.githubusercontent.com/101597718/232592684-fc3764fa-1272-487f-890f-c008cfab7bbc.png)
![arp2](https://user-images.githubusercontent.com/101597718/232592740-ecb8b2ca-7777-46b1-b2fa-1906787b3262.png)

- Skutočný výstup: 
```
timestamp: 2023-04-17T19:33:03.411+00:00
src MAC: 08:00:27:56:aa:92
dst MAC: 52:54:00:12:35:02
frame length: 42 bytes
src IP: 10.0.2.15
dst IP: 10.0.2.2
0x0000:  52 54 00 12  35 02 08 00  27 56 aa 92  08 06 00 01   RT..5... 'V......
0x0010:  08 00 06 04  00 01 08 00  27 56 aa 92  0a 00 02 0f   ........ 'V......
0x0020:  00 00 00 00  00 00 0a 00  02 02                      ........ ..

```

## Zdroje
- [Programing with pcap](https://www.tcpdump.org/pcap.html)
- [Converting from String to Enum in C](https://stackoverflow.com/questions/16844728/converting-from-string-to-enum-in-c)
- [What is the largest TCP/IP network port number allowable for IPv4?](https://stackoverflow.com/questions/113224/what-is-the-largest-tcp-ip-network-port-number-allowable-for-ipv4)
- [Parsing program options using getopt](https://www.gnu.org/software/libc/manual/html_node/Getopt.html)
- [Find the IPv4 network number and netmask for a device](https://www.tcpdump.org/manpages/pcap_lookupnet.3pcap.html)
- [PCAP-FILTER](https://www.wireshark.org/docs/man-pages/pcap-filter.html)
- [I'm trying to build an RFC3339 timestamp in C. How do I get the timezone offset?](https://stackoverflow.com/questions/48771851/im-trying-to-build-an-rfc3339-timestamp-in-c-how-do-i-get-the-timezone-offset)
- [C Date Time](https://zetcode.com/articles/cdatetime/)
- [Let's Build a Hexdump Utility in C](http://www.dmulholl.com/lets-build/a-hexdump-utility.html)
- [Is these a way to set the output of printf to a string?](https://stackoverflow.com/questions/19382198/is-these-a-way-to-set-the-output-of-printf-to-a-string)
- [Using libpcap in C](https://www.devdungeon.com/content/using-libpcap-c)
<br />
<br />
<br />


 