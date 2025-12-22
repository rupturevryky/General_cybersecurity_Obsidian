# GPG 
 
публичные ключи:
> `gpg -k`

приватные ключи:
>`gpg -K`

Создать свой ключ:
>`gpg --full-generate--key`
>
>Сгенерировать асимметричную ключевую пару без указания всех параметров:
>
>`gpg --gen-key`


Создать саб-ключ:
>`gpg --expert --edit-key {id получателя}`
>
> После неё открывается консоль gpg для ввода дальнейших команд. Посмотреть список всех команд: `?`.
>1. `addkey` - добавить новый subkey
>2. `save`
>3. `key {number}` - выбрать/снять_выбор саб-ключ(а) для редактирования
>4. `expire` - изменить дату истечения ключа

Когда ключ создан, он сохраняется в `~/.gnupg`
	1. `~/.gnupg/gpg.conf` - файл конфигурации
	2. `~/.gnupg/secring.gpg` - здесь секретная часть ключей
	3. `~/.gnupg/pubring.gpg` - здесь приватная часть ключей

Узнать алгоритм шифрования файла:
>`gpg --list-packets file.txt.gpg`

Узнать режим использования криптоалгоритма шифрования файла:
> `gpg --list-packets file.txt`
## Sign 
Подписать файл:
>`gpg --clearsing file.txt`

## Encrypt
Зашифровать файл:
>`gpg -r {id получателя} --armor --encrypt file.txt` 

расшифровать файл:
>`gpg -d file.txt.asc`

## Удаление secret-key
### Бэкап secrat-key
`gpg -a --export-secret-key {id получателя} > secret_key`

Его важно хранить в самом безопасном месте.
### Создание Revocation Certificate
`gpg -a --gen-rovoke {id получателя} > revocation_cert.gpg`

С помощью него можно отозвать свой секретный ключ. Его важно хранить в безопасном месте отдельно от секретного ключа.
### Экспор публичного ключа
`gpg -a --export {id получателя} > public_key.gpg`

### Удаление Primary Key
Для начала нужно экспортировать secret subkeys:
`gpg -a --export-secret-subkey {id получателя} > secret_subs.gpg`
Теперь удалить всю секретную часть ключа:
`gpg --delete-secret-keys {id получателя}`
При этом важно понимать, что остаётся публичная часть ключа в `~/.gnupg/pubring.gpg`: `gpg -k`
Но ничего не будет в `~/.gnupg/secret.gpg`: `gpg -K`
Теперь необходимо сделать импорт приватных саб-ключей, но без главного ключа: 
`gpg --import secret-subs.gpg`
## Удаление Public key
Просмотреть список доступных ключей:
>1. `gpg --list-keys`

Удалить нужный ключ
>2. `gpg --delete-keys {id ключа}`
## Скачать ключ
`gpg --import file.key`
