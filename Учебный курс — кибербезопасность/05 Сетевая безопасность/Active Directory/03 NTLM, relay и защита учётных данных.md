# NTLM, relay и защита учётных данных

NTLM — семейство challenge-response протоколов аутентификации Windows. Пароль по сети напрямую не передаётся, однако перехваченный обмен может быть использован для офлайн-проверки секрета или перенаправлен к другому сервису при подходящих условиях.

## Не путать

- **pass-the-hash** использует полученный NT hash как материал аутентификации;
- **NTLM relay** пересылает текущий обмен к сервису, который принимает его без достаточной привязки канала;
- **password spraying** проверяет небольшой набор паролей против многих учётных записей;
- **LLMNR/NBT-NS poisoning** провоцирует или перехватывает разрешение имён, чтобы получить попытку аутентификации.

## Меры защиты

- предпочитать Kerberos и поэтапно ограничивать NTLM после аудита совместимости;
- включать SMB signing там, где это поддерживается политикой, и LDAP signing/channel binding;
- отключать ненужные LLMNR и NetBIOS name resolution;
- применять Extended Protection for Authentication для поддерживаемых сервисов;
- не использовать привилегированные учётные данные на менее доверенных узлах;
- отслеживать необычные источники NTLM и аутентификацию между несвязанными системами.

Relay зависит от протокола, настроек подписи, типа учётной записи и прав на целевом сервисе. Увиденный NetNTLM-ответ ещё не означает успешный вход.

## Источники

- [Microsoft Learn: NTLM overview](https://learn.microsoft.com/windows-server/security/kerberos/ntlm-overview)
- [Microsoft: LDAP signing](https://learn.microsoft.com/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server)

