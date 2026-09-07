# Введение
  
  **theHarvester** — это простой, но полезный инструмент для сбора адресов электронной почты, банеров, виртуальных хостов, поддоменов, открытых портов и имен сотрудников из разных открытых источников.

---
# Использование

---

## Разведка по домену

   Для примера, соберем имена сотрудников работающих в **Microsoft** и имеющих профиль **LinkedIn**:
```
theHarvester -d microsoft.com --dns-server 8.8.8.8 -b linkedin
```
   Рассмотрим синтаксис, который использовался в команде:

`-d` — указывает целевую организацию с помощью доменного имени.
`--dns-server` — позволяет указать DNS-сервер для всех DNS-запросов.
`-b` — указывает источник для получения информации: **baidu**, **bing**, **bingapi**, **dogpile**, **google**, **googleCSE**, **googleplus**, **google-profiles**, **linkedin**, **pgp**, **twitter**, **vhost**, **yahoo**, **all**
   Другие параметры:

`-s` — начать с результата под номером X (по умолчанию: 0)
`-v` — проверить имя хоста через преобразование dns и поиск виртуальных хостов
`-f` — сохранить результаты в HTML и XML файлы (оба)
`-n` — выполнить обратный запрос по всем обнаруженным диапазонам
`-c` — выполнить брут-форс DNS для доменного имени
`-t` — обнаружение DNS TLD расширения
`-e` — использовать этот DNS сервер
`-l` — ограничить количество результатов для работы (bing идёт от 50 до 50 результатов, google с 100 до 100, а pgp не использует эту опцию).

---

# Модули 

Модули инструмента можно разделить на активные и пассивные.

**Пассивные**:
- anubis - https://github.com/jonluca/anubis
- bevigil - https://bevigil.com/osint-api
- baidu - www.baidu.com
- binaryedge - https://www.binaryedge.io
- bing - https://www.bing.com
- bingapi
- brave - https://search.brave.com/
- bufferoverun - https://tls.bufferover.run
- censys - https://censys.io
- certspotter - https://sslmate.com/certspotter/
- criminalip - https://www.criminalip.io
- crtsh - https://crt.sh (поиск по сертификатам)
- dnsdumpster - https://dnsdumpster.com
- duckduckgo - https://duckduckgo.com
- fullhunt - https://fullhunt.io
- github-code - www.github.com
- hackertarget - https://hackertarget.com
- hunter - https://hunter.io
- hunterhow - https://hunter.how
- intelx - http://intelx.io
- netlas - https://app.netlas.io
- onyphe - https://www.onyphe.io/
- otx - https://otx.alienvault.com
- pentestTools - https://pentest-tools.com/
- projecDiscovery - https://chaos.projectdiscovery.io
- rapiddns - https://rapiddns.io
- rocketreach - https://rocketreach.co
- securityTrails - https://securitytrails.com
- -s, --shodan - https://shodan.io
- sitedossier - http://www.sitedossier.com
- subdomaincenter - https://www.subdomain.center/ (поиск поддоменов)
- subdomainfinderc99 - https://subdomainfinder.c99.nl (поиск поддоменов)
- threatminer - https://www.threatminer.org/
- tomba - https://tomba.io
- urlscan - https://urlscan.io
- vhost
- virustotal - https://www.virustotal.com
- yahoo
- zoomeye - https://www.zoomeye.org

**Активные**:
- DNS bruteforce
- Screenshots - найденых поддоменов

Теперь попробуем найти поддомены с помощью поисковой системы Bing:
```
theHarvester -d microsoft.com -b bing
```
На скрине видно, что theHarvester нашел более 100 поддоменов и их IP-адреса.
![[Pasted image 20240706105738.png]]
Для оптимизации поиска, можно добавить имеющиеся API ключи к сторонним сервисам, таким как:
- binaryedge
- bing
- bufferoverun
- censys
- criminalip
- fullhunt
- github
- hunter
- hunterhow
- intelx
- netlas
- onyphe
- pentestTools
 - projecDiscovery
- rocketreach
- securityTrails
- shodan
- tomba
- zoomeye
- bevigil

Как вы видите, инструмент можно использовать для сбора данных как о сотрудниках, так и информацию об инфраструктуре организации, такая как поддомены и IP-адреса. Тулза часто используется для быстрого сбора данных об организации.



