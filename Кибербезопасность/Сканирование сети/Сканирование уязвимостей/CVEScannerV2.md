### Что это?

**[CVEScannerV2](https://github.com/scmanjarrez/CVEScannerV2)** - скрипт Nmap, который сканирует на наличие вероятных **уязвимостей** на основе **сервисов**, обнаруженных на **открытых портах**.  

### Применение​

С установкой у меня возникли **некоторые трудности**, но с запуском **через docker проблем не было никаких**. Для **запуска** потребуется ввести следующую **команду**:

``` bash
docker run -v /tmp/cvslogs:/tmp/cvslogs scmanjarrez/cvescanner --script-args log=/tmp/cvslogs/scan.log,json=/tmp/cvslogs/scan.json TARGET
```
После чего нас встретит вывод с уязвимостями.  

![[Pasted image 20260122181338.png]]