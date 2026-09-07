Чтобы найти аккаунт GitHub или GitLab по почту, выполните шаги:

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