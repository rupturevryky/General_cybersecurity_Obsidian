# PowerShell для администратора и аналитика

> [!abstract] Результат
> Ученик понимает объектный pipeline, безопасно получает сведения о Windows, использует help и отличает удобную политику запуска от контроля безопасности.

## Оболочка и язык

PowerShell — командная оболочка, язык сценариев и платформа управления. Cmdlet обычно имеет имя `Verb-Noun`, принимает параметры и возвращает объекты .NET, а не только текст.

```powershell
Get-Command *Process*
Get-Help Get-Process -Full
Get-Process | Get-Member
```

Сначала изучают тип объекта и свойства, затем строят фильтр. Парсинг визуально отформатированной таблицы — плохая стратегия.

## Pipeline

```powershell
Get-Process |
    Where-Object CPU -gt 100 |
    Sort-Object CPU -Descending |
    Select-Object Name,Id,CPU,Path
```

Pipeline передаёт объекты. Форматирование (`Format-Table`, `Format-List`) применяют в конце для человека; после него данные плохо подходят дальнейшей обработке.

## Переменные, коллекции и сравнение

```powershell
$cutoff = (Get-Date).AddHours(-1)
$events = Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$cutoff}
$events.Count
```

Операторы `-eq`, `-like`, `-match`, `-contains` имеют разную семантику. `-match` использует регулярное выражение. При обработке потенциально недоверенных данных избегают `Invoke-Expression`.

## Файлы и данные

```powershell
Get-ChildItem C:\Path -Force
Get-FileHash C:\Path\file.exe -Algorithm SHA256
Get-AuthenticodeSignature C:\Path\file.exe
Get-Content C:\Path\log.txt -Tail 100
```

Подпись подтверждает целостность относительно сертификата, но подписанный файл не автоматически безопасен. Hash идентифицирует содержимое, но не объясняет происхождение.

```powershell
$data | Export-Csv .\result.csv -NoTypeInformation
$data | ConvertTo-Json -Depth 5 | Set-Content .\result.json
```

## CIM

CIM предоставляет управляемую модель системы:

```powershell
Get-CimInstance Win32_OperatingSystem
Get-CimInstance Win32_Process
Get-CimInstance Win32_Service
```

Запрос должен выбирать только нужные свойства и учитывать стоимость на удалённых системах.

## Remoting

PowerShell Remoting выполняет команды в удалённой сессии, обычно через WinRM:

```powershell
Invoke-Command -ComputerName server -ScriptBlock { Get-Service }
Enter-PSSession -ComputerName server
```

Аутентификация, endpoint configuration, JEA и сетевые ограничения определяют полномочия. Делегирование credentials и «second hop» требуют отдельного проектирования.

## Execution Policy

Execution Policy помогает предотвращать непреднамеренный запуск неподходящих сценариев и задаёт правила подписания по scopes. Microsoft прямо не считает её системой безопасности: пользователь может обойти её доступными способами выполнения кода.

```powershell
Get-ExecutionPolicy -List
```

Не меняйте policy глобально ради одного скрипта без понимания происхождения и корпоративной политики.

## Секреты и история

Секрет в аргументе может попасть в историю, Event Log, список процессов или transcript. `SecureString` и SecretManagement решают отдельные задачи, но не делают любой сценарий безопасным автоматически.

## Ошибки и воспроизводимость

```powershell
$ErrorActionPreference = 'Stop'
try {
    Get-Item C:\Required\File
} catch {
    Write-Error $_
}
```

В аналитическом скрипте фиксируют входные данные, время, версию, ошибки и формат результата. Изменяющие команды отделяют от сбора сведений и требуют явного подтверждения.

## Вопросы для собеседования

1. Чем объектный pipeline отличается от текстового?
2. Зачем `Get-Member`?
3. Почему `Format-Table` ставят в конце?
4. Является ли Execution Policy границей безопасности?
5. Где может утечь секрет из аргумента команды?

## Рабочий сценарий

На внешней платформе соберите одним pipeline процессы с путём, владельцем и временем запуска, затем экспортируйте структурированный результат. Объясните каждое преобразование.

## Официальная документация

- [PowerShell execution policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies)
