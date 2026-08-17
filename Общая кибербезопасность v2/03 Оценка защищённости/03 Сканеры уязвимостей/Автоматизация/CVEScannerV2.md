---
topic: security-assessment
level: intermediate
status: legacy-tool-reference
last_reviewed: 2026-08-17
verified_against: https://hub.docker.com/r/scmanjarrez/cvescanner
---

> [!warning] Наследуемый образ
> Команда зависит от стороннего Docker-образа без закреплённого digest. Для нового курса используйте Nuclei или поддерживаемый сканер с SBOM/CVE-базой.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

### Что это?

**[CVEScannerV2](https://github.com/scmanjarrez/CVEScannerV2)** - скрипт Nmap, который сканирует на наличие вероятных **уязвимостей** на основе **сервисов**, обнаруженных на **открытых портах**.  

### Применение​

С установкой у меня возникли **некоторые трудности**, но с запуском **через docker проблем не было никаких**. Для **запуска** потребуется ввести следующую **команду**:

``` bash
docker run -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json TARGET
```
После чего нас встретит вывод с уязвимостями.  

![[Pasted image 20260122181338.png]]
