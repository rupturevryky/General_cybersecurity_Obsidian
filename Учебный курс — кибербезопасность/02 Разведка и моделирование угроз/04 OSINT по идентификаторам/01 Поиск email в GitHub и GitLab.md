---
topic: reconnaissance
level: intermediate
status: source-review-complete
last_reviewed: 2026-08-17
verified_against: https://docs.github.com/en/rest/commits/commits
---

# Публичные email в GitHub и GitLab

Email может присутствовать в профиле, commit metadata, issue или историческом объекте. Адрес автора commit не доказывает владельца аккаунта или актуальную работу в организации: Git допускает произвольные author name/email, а репозитории зеркалируются.

Ищите только в рамках разрешённой задачи, не проверяйте найденные адреса попытками входа и не сохраняйте лишние персональные данные. Связь подтверждают официальным доменом, подписанными commits, устойчивой историей и другими независимыми признаками.

> [!note] Проверка источников завершена
> Базовая линия: GitHub REST API. Исторические payload-примеры ниже сохранены для разбора, но не считаются рекомендацией для реальных систем; практику выполняйте только в назначенной лаборатории внешней учебной платформы и в пределах её правил.

> [!note] Статус материала
> Исходный конспект сохранён, но команды, версии, зависимости и внешние ссылки необходимо сверять с официальной документацией перед практикой.

## Исторический метод подстановки автора

Ниже сохранён старый пример, основанный на создании commit с чужим email. Его не следует выполнять: он создаёт ложный публичный артефакт, может затронуть третье лицо и нарушить правила платформы. Для защитной задачи анализируйте уже опубликованные разрешённые данные через поиск и API.

1. Создайте фиктивный репозиторий
``` bash
git clone <email_guess repo>
cd email_guess 
```
2. Сделайте коммит, но замените автора и используйте целевой email для подтверждения GitHub
```bash
echo "" > foo.txt
git add .
git commit -m "bar" --author="foo <target_mail@protonmail.com>"
git push origin master
```
3. Проверьте информацию о коммите в веб интерфейсе, чтобы найти учётную запись пользователя GitHub.

```
Merge: 84fa6be 6a26afa
Author: John Ripper <evilhaker42@gmail.com>
Date: Sat Jun 9 13:56:59 2019 -0400

	Merge pull request #4 from Prodicode/patch-1
	
	Added Steganography Online
	
commit
84fa6be948d608889bc3636248cffa3a3baaa578
Merge: d3d50b4 f500f15
Author: John Hammond <johnhammond@organization.com>
Date: Sat Jun 8 11:56:41 2019 -0400

	Merge pull request #6 from Abemarkar23/patch-1
	
	added a website for cryptography
```
