# Сеть и удалённое управление Windows

> [!abstract] Результат
> Ученик читает адреса, маршруты, DNS и сокеты Windows, различает SMB, RDP и WinRM и понимает роль firewall и профиля сети.

## Диагностические слои

Сетевую проблему проверяют снизу вверх:

1. состояние интерфейса;
2. IP-адрес и префикс;
3. маршрут и шлюз;
4. DNS;
5. firewall;
6. слушающий сокет;
7. прикладной протокол и аутентификация.

```powershell
Get-NetAdapter
Get-NetIPConfiguration
Get-NetIPAddress
Get-NetRoute
Get-DnsClientServerAddress
Resolve-DnsName example.org
Test-NetConnection example.org -Port 443
```

Успешный ping не доказывает доступность приложения, а неуспешный не доказывает недоступность TCP: ICMP может фильтроваться отдельно.

## Сокеты и процессы

```powershell
Get-NetTCPConnection -State Listen
Get-NetTCPConnection | Where-Object RemotePort -eq 443
Get-Process -Id (Get-NetTCPConnection -LocalPort 8080).OwningProcess
```

Привязка к `127.0.0.1` доступна только локально; `0.0.0.0` обычно означает все IPv4-интерфейсы. Сокет может слушать, но firewall способен блокировать входящий трафик.

## Профили firewall

Windows Defender Firewall применяет профили Domain, Private и Public. Профиль выбирается по контексту сети, а правила имеют направление, действие, протокол, адреса, порты, программу, службу и профиль.

```powershell
Get-NetConnectionProfile
Get-NetFirewallProfile
Get-NetFirewallRule -Enabled True | Select-Object -First 20
```

Не отключайте firewall для диагностики. Создавайте узкую гипотезу и исследуйте применяемое правило.

## SMB

SMB предоставляет файлы, принтеры и другие операции. UNC-путь имеет вид `\\server\share\path`. Доступ зависит от аутентификации, share permissions и ACL файловой системы.

Административные shares вроде `C$` предназначены для администрирования и требуют соответствующих прав. SMB signing, encryption и поддерживаемые dialects влияют на защищённость соединения.

```powershell
Get-SmbConnection
Get-SmbShare
Get-SmbSession
```

## RDP

RDP предоставляет интерактивный удалённый сеанс. Проверяют Network Level Authentication, сертификат, разрешённые группы, MFA/шлюз при наличии и область сетевого доступа. Публикация RDP напрямую в Интернет создаёт значительный риск.

## WinRM и PowerShell Remoting

WinRM реализует WS-Management и используется PowerShell Remoting. Он не равен RDP: вместо рабочего стола предоставляет управляемый командный контекст. В домене Kerberos способен аутентифицировать стороны; в других сценариях настройка доверия требует осторожности.

`TrustedHosts` не шифрует и не удостоверяет всё автоматически. HTTPS listener, Kerberos, сертификаты и ограничения endpoint решают разные задачи.

## Имена и контексты учётных данных

Подключение по IP может изменить выбор механизма аутентификации. Формы `COMPUTER\user`, `DOMAIN\user` и UPN задают разные области. Ошибка «Access denied» означает проблему авторизации или политики, а не обязательно неправильную сеть.

## Вопросы для собеседования

1. Почему listening socket может быть недоступен удалённо?
2. Чем SMB отличается от RDP и WinRM?
3. Как взаимодействуют share permissions и NTFS?
4. Почему ping — недостаточная проверка?
5. Что нужно проверить перед включением удалённого управления?

## Рабочий сценарий

Во внешней лаборатории `Test-NetConnection` видит порт WinRM, но вход не выполняется. Разделите гипотезы на сеть, listener, аутентификацию и авторизацию.
