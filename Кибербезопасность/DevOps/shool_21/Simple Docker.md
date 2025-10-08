## Part 1. Готовый докер

**Установить докер**:
``` shell
sudo apt install docker docker-compouse
```
**Установить Docker по умному:**
```bash
#!/bin/bash

# Preparation
sudo apt update -y
sudo apt install ca-certificates curl gnupg lsb-release -y
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update -y
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

# Add user htb-student to the Docker group
sudo usermod -aG docker htb-student
echo '[!] You need to log out and log back in for the group changes to take effect.'

# Test Docker installation
docker run hello-world
```

| **Команда**      | **Описание**                             |
| ---------------- | ---------------------------------------- |
| `docker ps`      | Вывод списка всех запущенных контейнеров |
| `docker stop`    | Остановите работающий контейнер.         |
| `docker start`   | Запустите остановленный контейнер.       |
| `docker restart` | Перезапустите работающий контейнер.      |
| `docker rm`      | Снимите контейнер.                       |
| `docker rmi`     | Удалите образ Docker.                    |
| `docker logs`    | Просмотр журналов контейнера.            |

```
# справочная информация
docker --help # список доступных команд
docker <command> --help # информация по команде 

docker --version # версия Docker
docker info # общая информация о системе 

# работа с образами
docker search debian # поиск образов по ключевому слову debian 

docker pull ubuntu # скачивание последней версии (тег по умолчанию latest) официального образа ubuntu (издатель не указывается) из репозитория по умолчанию docker.io/library
docker pull prom/prometheus # скачивание последней версии (latest) образа prometheus от издателя prom из репозитория docker.io/prom
docker pull docker.io/library/ubuntu:18.04 # скачивание из репозитория docker.io официального образа ubuntu с тегом 18.04 

docker images # просмотр локальных образов 

docker rmi <image_name>:<tag> # удаление образа. Вместо <image_name>:<tag> можно указать <image_id>. Для удаления образа все контейнеры на его основе должны быть как минимум остановлены
docker rmi $(docker images -aq) # удаление всех образов 

# работа с контейнерами
docker run hello-world # Hello, world! в мире контейнеров
docker run -it ubuntu bash # запуск контейнера ubuntu и выполнение команды bash в интерактивном режиме
docker run --name docker-getting-started --publish 8080:80 docker/getting-started # запуск контейнера gettind-started с отображением (маппингом) порта 8080 хоста на порт 80 внутрь контейнера
docker run --detach --name mongodb docker.io/library/mongo:4.4.10 # запуск контейнера mongodb с именем mongodb в фоновом режиме. Данные будут удалены при удалении контейнера! 

docker ps # просмотр запущенных контейнеров
docker ps -a # просмотр всех контейнеров (в том числе остановленных)
docker stats --no-stream # просмотр статистики 

docker start alpine # создание контейнера из образа alpine 

docker start <container_name> # запуск созданного контейнера. Вместо <container_name> можно указать <container_id>
docker start $(docker ps -a -q) # запуск всех созданных контейнеров 

docker stop <container_name> # остановка контейнера. Вместо <container_name> можно указать <container_id>
docker stop $(docker ps -a -q) # остановка всех контейнеров 

docker rm <container_name> # удаление контейнера. Вместо <container_name> можно указать <container_id>
docker rm $(docker ps -a -q) # удаление всех контейнеров 

# система
docker system info # общая информация о системе (соответствует docker info)
docker system df # занятое место на диске
docker system prune -af # удаление неиспользуемых данных и очистка диска
```

Рассмотрим два способа хранения данных контейнеров:

- [named volumes](https://docs.docker.com/get-started/05_persisting_data/) – именованные тома хранения данных  
    Позволяет сохранять данные в именованный том, который располагается в каталоге в /var/lib/docker/volumes и не удаляется при удалении контейнера. Том может быть подключен к нескольким контейнерам
    
- [bind mount](https://docs.docker.com/get-started/06_bind_mounts/) – монтирование каталога с хоста  
    Позволяет монтировать файл или каталог с хоста в контейнер. На практике используется для проброса конфигурационных файлов или каталога БД внутрь контейнера
    

Ниже приведены примеры использования named volume и bind mount:

```
# справочная информация
docker <command> --help 

# named volume
docker run --detach --name jenkins --publish 80:8080 --volume=jenkins_home:/var/jenkins_home/ jenkins/jenkins:lts-jdk11 # запуск контейнера jenkins с подключением каталога /var/jenkins_home как тома jenkins_home
docker volume ls # просмотр томов
docker volume prune # удаление неиспользуемых томов и очистка диска. Для удаления тома все контейнеры, в которых он подключен, должны быть остановлены и удалены 

# bind mount
# запуск контейнера node-exporter с монтированием каталогов внутрь контейнера в режиме read only: /proc хоста прокидывается в /host/proc:ro внутрь контейнера, /sys - в /host/sys:ro, а / - в /rootfs:ro
docker run \
-p 9100:9100 \
-v "/proc:/host/proc:ro" \
-v "/sys:/host/sys:ro" \
-v "/:/rootfs:ro" \
--name node-exporter prom/node-exporter:v1.1.2
```

**Скачивание официального образа Nginx**:
```shell
docker pull nginx
```
![[./assets_D05_SimpleDocker/Pasted image 20240809101541.png]]

**Проверка наличия образа**:
```shell
docker images
```
![[./assets_D05_SimpleDocker/Pasted image 20240809101627.png]]

**Запуск Docker-образа**:
```shell
docker run -d nginx
```
![[./assets_D05_SimpleDocker/Pasted image 20240809101708.png]]

**Проверка запущенных контейнеров**:
```shell
docker ps
```
![[./assets_D05_SimpleDocker/Pasted image 20240809101734.png]]

**Получение информации о контейнере**:
``` shell
docker inspect [container_id|container_name]
```
   ![[./assets_D05_SimpleDocker/Pasted image 20240809103104.png]]

   ![[./assets_D05_SimpleDocker/Pasted image 20240809103130.png]]

   ![[./assets_D05_SimpleDocker/Pasted image 20240809103154.png]]

   ![[./assets_D05_SimpleDocker/Pasted image 20240809103229.png]]

   ![[./assets_D05_SimpleDocker/Pasted image 20240809103247.png]]
   
   Отсюда:
   1. размер контейнера: `187603368` **байт** = - **`179.0` МБ**;
      
      ![[./assets_D05_SimpleDocker/Pasted image 20240809104345.png]]
   2. список замапленных портов: `80/tcp` основного хоста не мапится ни с каким другим портом;
      
      ![[./assets_D05_SimpleDocker/Pasted image 20240809103537.png]]
   3. ip контейнера: `172.17.0.2/16`
      
      ![[./assets_D05_SimpleDocker/Pasted image 20240809103719.png]]

**Остановка Docker-контейнера**:
``` shell
docker stop [container_id|container_name]
```
![[./assets_D05_SimpleDocker/Pasted image 20240809104528.png]]

![[./assets_D05_SimpleDocker/Pasted image 20240809104539.png]]

**Проверка остановки контейнера**:
```shell
docker ps
```
![[./assets_D05_SimpleDocker/Pasted image 20240809104554.png]]

**Запуск Docker с замапленными портами**:
```shell
docker run -d -p 80:80 -p 443:443 nginx
```
![[./assets_D05_SimpleDocker/Pasted image 20240809104700.png]]

**Проверка доступности стартовой страницы Nginx**:
> Открыть браузер и перейдите по адресу `http://localhost:80`. Там должна быть стартовая страница Nginx.

> ![[./assets_D05_SimpleDocker/Pasted image 20240809105059.png]]

**Перезапуск Docker-контейнера**:
``` shell
docker restart [container_id|container_name]
```

![[./assets_D05_SimpleDocker/Pasted image 20240809105207.png]]

**Умная установка Apache через Dockerfile:**
```bash
# Use the latest Ubuntu 22.04 LTS as the base image
FROM ubuntu:22.04

# Update the package repository and install the required packages
RUN apt-get update && \
    apt-get install -y \
        apache2 \
        openssh-server \
        && \
    rm -rf /var/lib/apt/lists/*

# Create a new user called "docker-user"
RUN useradd -m docker-user && \
    echo "docker-user:password" | chpasswd

# Give the docker-user user full access to the Apache and SSH services
RUN chown -R docker-user:docker-user /var/www/html && \
    chown -R docker-user:docker-user /var/run/apache2 && \
    chown -R docker-user:docker-user /var/log/apache2 && \
    chown -R docker-user:docker-user /var/lock/apache2 && \
    usermod -aG sudo docker-user && \
    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Expose the required ports
EXPOSE 22 80

# Start the SSH and Apache services
CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND
```

---

## Part 2. Операции с контейнером

1. **Чтение конфигурационного файла nginx.conf внутри контейнера**:
   ```shell
   docker exec -it <container_id> cat /etc/nginx/nginx.conf
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810174809.png]]

2. **Создание файла nginx.conf на локальной машине с настройкой по пути _/status_ отдачи страницы статуса сервера nginx**:
   
   ![[./assets_D05_SimpleDocker/Pasted image 20240810180258.png]]

3. **Копирование файла nginx.conf внутрь контейнера**:
   ``` shell
   docker cp nginx.conf <container_id>:/etc/nginx/nginx.conf
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810175454.png]]

4. **Перезапуск nginx внутри контейнера**:
   ```shell
   docker exec -it <container_id> nginx -s reload
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810180135.png]]

5. **Проверка страницы статуса**:
   
   ![[./assets_D05_SimpleDocker/Pasted image 20240810181451.png]]

6. **Экспортируй контейнер в файл `container.tar` через команду `export`**:
   ```shell
   docker export <container_id> > container.tar
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810181706.png]]

7. **Останови контейнер**:
   ```shell
   docker stop <container_id>
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810181803.png]]

8. **Удали образ через `docker rmi [image_id|repository]`, не удаляя перед этим контейнеры**:
   ```shell
   docker rmi <image_id|repository>
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810182103.png]]
   
   Здесь `-f` - force.

9. **Удали остановленный контейнер**:
   ```shell
   docker rm <container_id>
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810182332.png]]

10. **Импортируй контейнер обратно через команду `import`**:
   ```shell
 cat container.tar | docker import - <new_image_name>  
 ```
 ![[./assets_D05_SimpleDocker/Pasted image 20240810182548.png]]

11. **Запусти импортированный контейнер**:
   ```shell
   docker run -d -p 80:80 <new_image_name>
   ```
   ![[./assets_D05_SimpleDocker/Pasted image 20240810185725.png]]

12. **Проверь, что по адресу `localhost:80/status` отдается страничка со статусом сервера nginx**:
   
   ![[./assets_D05_SimpleDocker/Pasted image 20240810185705.png]]

---

## Part 3. Мини веб-сервер

**`hello_page.c`:**

![[./assets_D05_SimpleDocker/Pasted image 20240811222502.png]]

> Установка зависимостей:
>
> ```shell
> sudo apt install libfcgi-dev
> sudo apt install spawn-fcgi
> ```

> Компиляция файла:
> 
> ```shell
> gcc hello_page.c -o hello_page -lfcgi 
> ```

**Запуск мини-сервер через `spawn-fcgi` на порту `8080`:**
``` shell
spawn-fcgi -p 8080 ./hello_page 
```
![[./assets_D05_SimpleDocker/Pasted image 20240811222550.png]]

**Конфигурация Nginx:**

![[./assets_D05_SimpleDocker/Pasted image 20240811222612.png]]
```shell
sudo nginx -s reload
```

Браузер:

![[./assets_D05_SimpleDocker/Pasted image 20240811222639.png]]

---

## Part 4. Свой докер

```dockerfile
# Используем базовый образ с установленным Nginx
FROM nginx

# Копируем исходный код приложения в контейнер
COPY ./server/hello_page.c /usr/src/hello.c
COPY ./server/start_server.sh /usr/src/start_server.sh
# Копируем конфигурационный файл nginx внутрь контейнера
COPY ./nginx/nginx.conf /etc/nginx/nginx.conf

# Устанавливаем необходимые пакеты для сборки FastCGI приложения
RUN apt-get update && apt-get install -y gcc spawn-fcgi libfcgi-dev

# Запуск
ENTRYPOINT ["bash", "/usr/src/start_server.sh"]
```

```nginx.conf
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    #include /etc/nginx/conf.d/*.conf;  # this is commented (!)

    server {
        listen 81;  # http://nginx.org/en/docs/http/ngx_http_core_module.html#listen
        location / {
            fastcgi_pass localhost:8080;  # https://nginx.org/ru/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass
        }
        location /status {
            stub_status on;
        }
    }
}

```

Сборка **Docker** образа:
> Перейти в директорию, содержащую `Dockerfile` и папки `nginx`, `server`
```shell
#!/usr/bin/env bash

docker build . -t server:v2

docker images

docker run --rm -d -p 80:81 -v ./nginx:/etc/nginx --name server2 server:v2

printf "The sever is up. Press <Enter> to stop it.\n"
read -p "Time to stop? " -r

docker stop server2
```

Эта команда запускает контейнер в фоновом режиме (`-d`), маппит порт 80 на хосте к порту 81 в контейнере (`-p 80:81`), и маппит текущую папку `./nginx` в папку `/etc/nginx` внутри контейнера.

![[./assets_D05_SimpleDocker/Pasted image 20240901120653.png]]

**Проверка доступа к серверу.**

Теперь можно проверить доступность сервера на `http://localhost:80`:
- Перейдите по `http://localhost:80` в браузере, чтобы увидеть страницу "Hello World!".
- Перейдите по `http://localhost:80/status` для получения статуса Nginx.

![[./assets_D05_SimpleDocker/Pasted image 20240901120900.png]]

![[./assets_D05_SimpleDocker/Pasted image 20240810185705.png]]

**Изменение конфигурации Nginx.**

Чтобы внести изменения в конфигурацию Nginx, отредактируйте файл `./nginx/nginx.conf`. После сохранения файла, перезапустите контейнер:
```shell
docker restart <container_id>
```

---

## Part 5. **Dockle**

Проверка до исправления:

![[./assets_D05_SimpleDocker/Pasted image 20240907144931.png]]

Исправление:
```dockerfile
# Используем базовый образ Debian
FROM debian:bookworm-slim

# Обновляем пакеты и устанавливаем необходимые зависимости, включая NGINX
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    nginx curl gcc spawn-fcgi libfcgi-dev build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    useradd mini_serv; \
    chown -R mini_serv:mini_serv /etc/nginx/nginx.conf; \
    chown -R mini_serv:mini_serv /var/cache/nginx; \
    chown -R mini_serv:mini_serv /home/; \
    chown -R mini_serv:mini_serv /var/log/nginx /var/lib/nginx; \
    touch /var/run/nginx.pid && chown -R mini_serv:mini_serv /var/run/nginx.pid; \
    chmod u-s /usr/bin/gpasswd; \
    chmod u-s /usr/bin/chsh; \
    chmod u-s /usr/bin/chfn; \
    chmod g-s /usr/bin/expiry; \
    chmod u-s /usr/bin/passwd; \
    chmod g-s /sbin/unix_chkpwd; \
    chmod g-s /usr/bin/chage; \
    chmod g-s /usr/bin/wall; \
    chmod u-s /bin/umount; \
    chmod u-s /bin/mount; \
    chmod u-s /usr/bin/newgrp; \
    chmod u-s /bin/su; \
    chmod u-s /usr/bin/chsh;

WORKDIR /home/
# Копируем файлы
COPY ./hello_page.c ./hello.c
COPY ./start_server.sh .
COPY ./nginx.conf /etc/nginx/nginx.conf

# Переключаемся на пользователя mini_serv для запуска NGINX
USER mini_serv

# Определяем команду запуска
ENTRYPOINT ["bash", "./start_server.sh"]
```

``` nginx.conf
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    #include /etc/nginx/conf.d/*.conf;  # this is commented (!)

    server {
        listen 81;  # http://nginx.org/en/docs/http/ngx_http_core_module.html#listen
        location / {
            fastcgi_pass localhost:8080;  # https://nginx.org/ru/docs/http/ngx_http_fastcgi_module.html#fastcgi_pass
        }
        location /status {
            stub_status on;
        }
    }
}
```
```start_server.sh
#!/usr/bin/env bash


gcc ./hello.c -l fcgi -o ./fcgi_server
spawn-fcgi -p 8080 ./fcgi_server
nginx -g 'daemon off;'
nginx -s reload

```

Итог:

![[./assets_D05_SimpleDocker/Pasted image 20240907172833.png]]

(команды)
``` shell
docker build . -t server:v3
```
```shell
dockle -ak NGINX_GPGKEY -ak NGINX_GPGKEY_PATH server:v3
```
```shell
docker run --rm -it -d -p 80:81 --name server3 server:v3
```
```shell
docker stop server3
```

---

## Part 6. Базовый **Docker Compose**

```docker_compose.yml
version: "3.9"

services:
  mini_serv:
    image: server:v4
    build: ../part_5
    container_name: server4

  nginxer:
    image: nginx:latest
    container_name: nginxer
    ports:
      - 80:8080
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
```
```nginx.conf
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    keepalive_timeout  65;

    #gzip  on;

    #include /etc/nginx/conf.d/*.conf;  # this is commented (!)

    server {
        listen 8080;
        location / {
            proxy_pass http://server4:81;
        }
        location /status {
            stub_status on;
        }
    }
}
```

Запуск сборки:

``` shell
docker-compose build
```
```shell
docker-compose up
```

Проверка:

![[./assets_D05_SimpleDocker/Pasted image 20240909162317.png]]