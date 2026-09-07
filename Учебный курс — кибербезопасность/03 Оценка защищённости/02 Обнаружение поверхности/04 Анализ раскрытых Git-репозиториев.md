---
topic: security-assessment
level: intermediate
status: technical-review-complete
last_reviewed: 2026-08-17
verified_against: https://github.com/internetwache/GitTools
---

> [!warning] Проверено для лаборатории
> GitTools применяется только к собственному намеренно раскрытому `.git`. Для поиска секретов используйте актуальный TruffleHog и не передавайте его install script прямо в shell без проверки.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

# Анализ раскрытых Git-репозиториев

## Введение

При обнаружении `.git` можно выкачать исходные файлы для анализа. Полезен инструмент [GitTools](https://github.com/internetwache/GitTools/tree/master).

А также есть инструменты: truffleHog, Repo Security Scaner.

## GitTools
## Gitdumper

gitdumper используется для извлечения всех доступных ссылок и журналов из `/.git`.
``` bash
./gitdumper.sh https://domain.com/.git git-dimp
```

## Extractor

После дампа репозитория стоит использовать инструмент `extractor` для извлечения файлов из каталога `/.git`.
```bash
./extractor.sh git-dump/ git-ext
```

После извлечения каталога `/.git` можно проанализировать файлы.


## TruffleHog

Инструмент выгружает все чувствительные данные из Git по названию организации (скорее всего имя профиля GitHub/GitLab)

[GitHub - trufflesecurity/trufflehog: Find, verify, and analyze leaked credentials](https://github.com/trufflesecurity/trufflehog)

Установка:
```
curl -fL -o trufflehog-install.sh https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh
less trufflehog-install.sh
sudo sh trufflehog-install.sh -s -- -b /usr/local/bin
trufflehog --version
```

Использование:
```
trufflehog github org=<ОРГАНИЗАЦИЯ>
```

Пример:
```
sudo trufflehog git https://github.com/trufflesecurity/test_keys
```
или
``` 
sudo trufflehog github --org=trufflesecurity
```
