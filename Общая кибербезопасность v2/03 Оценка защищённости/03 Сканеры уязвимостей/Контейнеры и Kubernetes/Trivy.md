---
topic: security-assessment
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://www.trivy.dev/docs/latest/getting-started/installation/
---

> [!note] Проверено для Trivy 0.72.0
> В актуальном CLI тип цели указывается явно: `trivy image`, `trivy fs`, `trivy repo` и т. д. Официальный контейнер доступен как `aquasec/trivy`; для воспроизводимых лабораторных работ фиксируйте версию образа.

```bash
trivy --version
trivy image python:3.4-alpine
trivy image --input image.tar
docker run --rm aquasec/trivy:0.72.0 --version
```

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

# Введение 

[Trivy](https://spy-soft.net/docker-vulnerabilities-scanner-trivy/) — сканер безопасности артефактов и конфигураций. Связанный материал: [[kube-hunter]]. Сравнивать эти инструменты напрямую следует осторожно: они решают разные задачи, а поддерживаемые цели и режимы необходимо сверять с официальной документацией.

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
trivy image python:3.4-alpine
```
Результат — ниже.

|   |   |
|---|---|
|1<br><br>2<br><br>3<br><br>4<br><br>5<br><br>6<br><br>7<br><br>8<br><br>9<br>|Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)<br><br>+---------+------------------+----------+-------------------+---------------+<br><br>\| LIBRARY \| VULNERABILITY ID \| SEVERITY \| INSTALLED VERSION \| FIXED VERSION \| TITLE \|<br><br>+---------+------------------+----------+-------------------+---------------+<br><br>\| openssl \| CVE-2019-1543 \| MEDIUM \| 1.1.1a-r1 \| 1.1.1b-r1 \| openssl: ChaCha20-Poly1305 \|<br><br>\| \| \| \| \| \| with long nonces \|<br><br>+---------+------------------+----------+-------------------+---------------+|

Можно сканировать образы в виде файлов:
```
trivy image --input image.tar
```
За формат вывода отвечает ключ `-f`, который можно выставить в **json**. Есть также поддержка вывода по кастомному шаблону.

Чтобы показать только определенные типы найденных уязвимостей, нужно указать ключ `--severity` и через запятую перечислить категории для отображения (**UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL**).
