---
topic: reconnaissance
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/six2dez/reconftw
---

# reconFTW

> [!success] Проверено
> Синтаксис сверён с официальным репозиторием. reconFTW объединяет пассивные и активные модули; сначала используйте `--dry-run` и `--check-tools`.

Инструмент все в одном для автоматического исследования хоста путем запуска наилучшего набора средств сканирования и обнаружения уязвимостей`

## 🏃‍♂️ Установка:
```
git clone https://github.com/six2dez/reconftw
cd reconftw/
./install.sh
./reconftw.sh --check-tools
./reconftw.sh -d example.com -r --dry-run
```

## ⚙️ Режимы:

Single Target
```
./reconftw.sh -d example.com -r
```


List of Targets
```
./reconftw.sh -l sites.txt -r -o ./output/
```

Режим `--all` включает активные проверки и не подходит для первичного запуска:
```
./reconftw.sh -d authorized.example -a
```

Deep scan
```
./reconftw.sh -d target.com -r --deep -o /output/directory/
```

Recon in a multi domain target
```
./reconftw.sh -m company -l domains_list.txt -r
```

## Некоторые возможности

## Osint
Domain information
Emails addresses and passwords leaks
Metadata finder
API leaks search

## Subdomains
Certificate transparency
NOERROR subdomain discovery
Bruteforce
Permutations
JS files & Source Code Scraping
DNS Records

## Hosts
IP info
CDN checker
WAF checker
Port Scanner
Port services vulnerability checks
Password spraying
Geolocalization info

## Webs
Web Prober
Web screenshoting
Web templates scanner
CMS Scanner
Url extraction
Favicon Real IP
Fuzzing
Wordlist generation
Passwords dictionary creation

## Vulnerability checks
XSS
Open redirect
SSRF
CRLF
Cors
LFI Checks
SQLi Check
SSTI
SSL tests
4XX Bypasser
