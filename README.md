# DNS Monitor

**Autor:** Adam Pastierik \
**Login:** xpasti00 \
**Dátum vytvorenia:** 20.10.2024

## Popis programu

DNS Monitor je aplikácia napísaná v C++ na analýzu a monitorovanie a výpis informácií DNS správ v sieti. Program spracováva zachytené pakety zo sieťového rozhrania alebo .pcap súboru a rozpoznáva medzi formátmi IPv4 a IPv6. Implementovaná funkcionalita zahŕňa detekciu typu linkovej vrstvy (Ethernet alebo Linux cooked mode), identifikáciu verzie IP, a spracovanie obsahu DNS správ z UDP paketov. Aplikácia podporuje záznamy typu A, AAAA, NS, MX, SOA, CNAME a SRV. Okrem spracovania týchto typov záznamov aplikácia poskytuje aj výpis doménových mien a ich prekladov na IP adresy.

## Preklad a spustenie

```
make
```

```bash
./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
```

-i: určuje sieťové rozhranie, z ktorého sa budú zachytávať DNS pakety. \
-p: určuje pcap súbor, ktorý sa bude analyzovať, ak sa nepoužíva sieťové rozhranie. \
-v: nastaví mód s podrobným výstupom (verbose mode). \
-d: určuje cestu k súboru, kde sa budú ukladať preložené domény. \
-t: určuje cestu k súboru s prekladmi domén na IP adresy.

## Zoznam odovzdaných súborov

- main.cpp
- arg_parser.cpp
- arg_parser.hpp
- dns_monitor.cpp
- dns_monitor.hpp
- section.cpp
- section.hpp
- Makefile
- README.md
- manual.pdf
