# scoring_api

В Scoring API реализован декларативный язык описания и систему валидации запросов к HTTP API сервиса скоринга. 
Функционал подсчета скора в `scoring.py`. API необычно тем, что пользователи дергают методы
POST запросами. Чтобы получить результат пользователь отправляет в POST запросе валидный JSON определенного формата
на локейшн `/method`.


**Цель проекта**: применить знания по ООП на практике, получить навык разработки нетривиальных объектно-ориентированных
программ. Это даст возможность быстрее и лучше понимать сторонний код (библиотеки или сервисы часто бывают написаны
с примененем ООП парадигмы или ее элементов), а также допускать меньше ошибок при проектировании сложных систем.


### Структура запроса

* `{"account": "<имя компании партнера>", "login": "<имя пользователя>", "method": "<имя метода>", "token": "
<аутентификационный токен>", "arguments": {<словарь с аргументами вызываемого метода>}}`

* `account` - строка, опционально, может быть пустым

* `login` - строка, обязательно, может быть пустым

* `method` - строка, обязательно, может быть пустым

* `token` - строка, обязательно, может быть пустым

* `arguments` - словарь (объект в терминах json), обязательно, может быть пустым

__Валидация__
запрос валиден, если валидны все поля по отдельности

Структура ответа

OK:
`{"code": <числовой код>, "response": {<ответ вызываемого метода>}}`
Ошибка:
`{"code": <числовой код>, "error": {<сообщение об ошибке>}}`

Аутентификация:
В случае если не пройдена, возвращается `{"code": 403, "error": "Forbidden"}`


### Методы


####Online_score

Аргументы:

* `phone` - строка или число, длиной 11, начинается с 7, опционально, может быть пустым

* `email` - строка, в которой есть @, опционально, может быть пустым

* `first_name` - строка, опционально, может быть пустым

* `last_name` - строка, опционально, может быть пустым

* `birthday` - дата в формате DD.MM.YYYY, с которой прошло не больше 70 лет, опционально, может быть пустым

* `gender` - число 0, 1 или 2, опционально, может быть пустым

__Валидация аругементов__: аргументы валидны, если валидны все поля по отдельности и если присутсвует хоть одна пара
`phone-email`, `first name-last name`, `gender-birthday` с непустыми значениями.

Контекст в словарь контекста должна прописываться запись "has" - список полей, которые были не пустые для данного
запроса

В ответ выдается число, полученное вызовом функции `get_score`. Но если пользователь админ, то отается всегда 42.

`{"score": <число>}`,
или если запрос пришел от валидного пользователя _admin_
`{"score": 42}`. Пример `{"code": 200, "response": {"score": 5.0}}`

Если произошла ошибка валидации
`{"code": 422, "error": "<сообщение о том какое поле(я) невалидно(ы) и как именно>"}`


#### Сlients_interests.
Аргументы

`client_ids` - массив числе, обязательно, не пустое

`date` - дата в формате DD.MM.YYYY, опционально, может быть пустым

__Валидация аругементов__: аргументы валидны, если валидны все поля по отдельности.
Контекст в словарь контекста должна прописываться запись "nclients" - количество id'шников, переденанных в запрос

```
$ curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method":
"online_score", "token":
"55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd
"arguments": {"phone": "79175002040", "email": "dev@otus.ru", "first_name": "Ann", "last_name":
"B", "birthday": "01.01.1990", "gender": 2}}' http://127.0.0.1:8080/method/ 
```

Ответ в ответ выдается словарь `<id клиента>:<список интересов>` . Список генерировать вызовом функции get_interests.

`{"client_id1": ["interest1", "interest2" ...], "client2": [...] ...}`
или если произошла ошибка валидации
`{"code": 422, "error": "<сообщение о том какое поле(я) невалидно(ы) и как именно>"}`

Пример

`{"code": 200, "response": {"1": ["books", "hi-tech"], "2": ["pets", "tv"], "3": ["travel", "music"], "4":
["cinema", "geek"]}}`


