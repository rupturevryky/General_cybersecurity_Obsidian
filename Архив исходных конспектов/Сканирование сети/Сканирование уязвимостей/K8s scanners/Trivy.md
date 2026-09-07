# Введение 

[Trivy](https://spy-soft.net/docker-vulnerabilities-scanner-trivy/) — eще один сканер безопасности контейнеров того же разработчика (Aquasec). Для bug bounty пригоден куда меньше [[Kube-hunter]], но довольно точен и быстр. Специализируется конкретно на **Docker**. Устанавливается чуть сложнее, чем **Kube-hunter**.

---

# Установка

Для установки в Debian, Ubuntu и Kali можно использовать следующий скрипт:
``` 
sudo apt-get install wget apt-transport-https gnupg lsb-release

wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -

echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee -a /etc/apt/sources.list.d/trivy.list

sudo apt-get update
sudo apt-get install trivy
```

---

# Использование
После этого можно сканировать. Для этого просто выполните `trivy [IMAGE_NAME]`. Например:
```
trivy python:3.4-alpine
```
Результат — ниже.

|   |   |
|---|---|
|1<br><br>2<br><br>3<br><br>4<br><br>5<br><br>6<br><br>7<br><br>8<br><br>9<br>|Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)<br><br>+---------+------------------+----------+-------------------+---------------+<br><br>\| LIBRARY \| VULNERABILITY ID \| SEVERITY \| INSTALLED VERSION \| FIXED VERSION \| TITLE \|<br><br>+---------+------------------+----------+-------------------+---------------+<br><br>\| openssl \| CVE-2019-1543 \| MEDIUM \| 1.1.1a-r1 \| 1.1.1b-r1 \| openssl: ChaCha20-Poly1305 \|<br><br>\| \| \| \| \| \| with long nonces \|<br><br>+---------+------------------+----------+-------------------+---------------+|

Можно сканировать образы в виде файлов:
```
trivy --input image.tar
```
За формат вывода отвечает ключ `-f`, который можно выставить в **json**. Есть также поддержка вывода по кастомному шаблону.

Чтобы показать только определенные типы найденных уязвимостей, нужно указать ключ `--severity` и через запятую перечислить категории для отображения (**UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL**).
