Инструмент все в одном для автоматического исследования хоста путем запуска наилучшего набора средств сканирования и обнаружения уязвимостей`

## 🏃‍♂️ Установка:
```
git clone https://github.com/six2dez/reconftw
cd reconftw/
./install.sh
./reconftw.sh -d target.com -r
```

## ⚙️ Режимы:

Single Target
```
sudo ./reconftw.sh -d target.com -r
```


List of Targets
```
sudo ./reconftw.sh -l sites.txt -r -o /output/directory/
```

Yolo mod (all tasks)
```
sudo ./reconftw.sh -d target.com -a
```

Deep scan
```
./reconftw.sh -d target.com -r --deep -o /output/directory/
```

Recon in a multi domain target
```
./reconftw.sh -m company -l domains_list.txt -r
```

# 🔥 Некоторые возможности:

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