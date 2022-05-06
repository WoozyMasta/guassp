<!-- omit in toc -->
# Guassp - GitLab User Access Synchronizer for SonarQube Projects

**Guassp** —
**Синхронізатор доступу користувачів GitLab для проектів SonarQube**

Проект призначений для створення розрахованої на багато користувачів
інтеграції [SonarQube][] та [GitLab][]. Бачимість проекту та дозволи
користувачів будуть встановлені в SonarQube таким же чином, як дозволи
для проекту в GitLab.

> Цей документ доступний мовами: [eng 🇬🇧][], [ua 🇺🇦][], [rus 🇷🇺][]

* [Реалізація](#реалізація)
* [Компоненти](#компоненти)
* [Зображення контейнерів](#зображення-контейнерів)
* [Швидкий старт](#швидкий-старт)
* [Конфігурація](#конфігурація)
* [API](#api)
* [Пайплайн](#пайплайн)
* [Метрики](#метрики)
* [Складання та налагодження проекту](#складання-та-налагодження-проекту)

## Реалізація

Цей застосунок складається з **API** інтерфейсу, який приймає запити на
оновлення дозволів з конвеєра GitLab CI, де вся довіра [побудована
навколо][jt] `CI_JOB_TOKEN`, довірені завдання додаються до черги
завдань RQ (Redis Queue). Завдання обробляються бекенд-воркерами Worker,
а для виведення статистики використовується окремий експортер метрик
prometheus.

![scheme][]

Права доступу видаються за рівнем доступу ролей SonarQube відповідно до
наявних дозволів користувачів проекту в GitLab.  
Враховується те, як GitLab реалізує права доступу користувачів у
проекті, та користувачів із запрошених груп, де рівні доступу імітуються
відповідно до GitLab.

![permissions][]  
![role-mapping][]

* [Реалізація](#реалізація)
* [Компоненти](#компоненти)
* [Зображення контейнерів](#зображення-контейнерів)
* [Швидкий старт](#швидкий-старт)
* [Конфігурація](#конфігурація)
* [API](#api)
* [Пайплайн](#пайплайн)
* [Метрики](#метрики)
* [Складання та налагодження проекту](#складання-та-налагодження-проекту)

## Компоненти

Проект реалізований на [flask][], для WSGI застосований [bjoern][],
робота з API GitLab відбувається через [python-gitlab][], а SonarQube
API через [python-sonarqube-api][]. Для обробки черги повідомлень
використовується [RQ][rq], чиї метрики віддає [rq-exporter][].

## Зображення контейнерів

Ви можете отримати зображення з регістрів:

* [`ghcr.io/woozymasta/guassp:latest`][ghcr]
* [`quay.io/woozymasta/guassp:latest`][quay]
* [`docker.io/woozymasta/guassp:latest`][dhub]

## Швидкий старт

Для швидкого старту можна використати приклад із [docker-compose][]:

1. [docker-compose.env][] - змініть налаштування у файлі налаштувань оточення
2. [docker-compose.yml][] - виконайте `docker-compose up -d`

## Конфігурація

Щоб запустити потрібну утиліту, передайте в контейнер або сценарій
`guassp.sh` аргумент:

* `worker` _(за замовчуванням)_ - процесор завдань для черги;
* `api` - API для контролю завдань;
* `exporter` - prometheus метрики;
* `all-in-one` - запуск `worker`, `api` та `exporter` одразу;
* `API -DEV` - запуск API через сервер Flask Dev.

### Параметри застосунку

* **`LISTEN_ADDRESS`**=`0.0.0.0` - Хост для публікації API;
* **`LISTEN_PORT`**=`5000` - Порт для публікації API;
* **`LOG_LEVEL`**=`INFO` - Рівень логування;
* **`SECRET_KEY`**=`secret` - Секретний ключ;
* **`QUEUE_RESULT_TTL`**=`7200` - Час зберігання результатів черги;
* **`MORE_ACCURATE_SYNC`**=`true` - Пошук користувачів у SonarQube
  електронною поштою GitLab, інакше пошук відбувається на ім'я
  користувача. Це викликає ще один запит API для кожного користувача, це
  більш точно, але повільніше вдвічі.

### Параметри роботи з GitLab

* **`GITLAB_URL`**=`https://gitlab.com` - Адреса сервера GitLab;
* **`GITLAB_TOKEN`** - Токен доступу до GitLab, повинен мати права на
  перегляд учасників та їх прав доступу для проектів, що обслуговуються;
* **`GITLAB_SKIP_USERS`** - Список (розділених комою) ID користувачів,
  які будуть пропущені при синхронізації.

### Параметри роботи з SonarQube

* **`SONARQUBE_URL`** - Адреса сервера SonarQube;
* **`SONARQUBE_TOKEN`** - Токен доступу до SonarQube з адміністративними
  привілеями;
* **`SONARQUBE_ALM_KEY`** - Ключ [ALM][] (назва) інтеграції з GitLab;
* **`SONARQUBE_SKIP_GROUPS`** - Список (розділених комою) груп,
  які будуть проігноровані при синхронізації.

### Параметри роботи з Redis

* **`REDIS_URL`**=`redis://localhost:6379/0` - URL-адреса підключення до
  сервера Redis.

### Параметри експортера метрик Prometheus

* **`EXPORTER_LISTEN_ADDRESS`**=`0.0.0.0` - Хост для публікації
  Prometeus метрик;
* **`EXPORTER_LISTEN_PORT`**=`9726` - Порт для публікації Prometeus метрик.

## API

### Реєстрація завдання

> POST **`/task`**
>
> ```json
> {"job_token": str}
> ```
>
> Headers: `JOB-TOKEN` or `Authorization: Bearer`

Потрібно передати токен завдання у будь-якому з варіантів:

```bash
curl -sL http://127.0.0.1:5000/task \
  -H "Content-Type: application/json" \
  -d '{"job_token": "'$CI_JOB_TOKEN'"}' | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "Authorization: Bearer $CI_JOB_TOKEN" | jq
```

Токен завдання може бути переданий заголовком `JOB-TOKEN` або
`Authorization: Bearer` або бути значенням ключа `job_token` у JSON

### Черга завдань

> GET **`/tasks`**

```bash
curl -sL http://127.0.0.1:5000/tasks | jq
curl -sL http://127.0.0.1:5000/tasks | jq -er '.tasks | keys'
```

### Статус завдання

> GET **`/task/<job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e | jq
```

### Видалення завдання з черги

> DELETE **`/task/<job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e \
  -X DELETE | jq
```

## Пайплайн

У пайплайні GitLab CI в першу чергу потрібно переконатися, що
налаштування [ALM][] зроблено та відноситься до вашого проекту, після
чого можна надсилати завдання на синхронізацію в guassp. Ось тепер можна
розпочинати аналіз проекту.

Для публікації API Guassp за Nginx як частини API SonarQube, дивіться до
[прикладу конфігурації Nginx][]

```bash
: "${SONARQUBE_PROJECT_KEY:=gitlab:$CI_PROJECT_ID}"

curl --location --fail --user "$SONARQUBE_TOKEN:" \
  "$SONARQUBE_URL/api/alm_settings/set_gitlab_binding" \
  -d "almSetting=$SONARQUBE_ALM_NAME" \
  -d "project=$SONARQUBE_PROJECT_KEY" \
  -d "repository=$CI_PROJECT_ID"

curl --location --fail -X POST -H "JOB-TOKEN: $CI_JOB_TOKEN" \
  "$SONARQUBE_URL/api/guassp/task"
```

Більш об'ємний приклад скрипту виконання SonarQube у пайплайні ви можете
побачити у файлі
[`sq-integration-taks.sh`][sq-integration-taks]

## Метрики

Метрики реалізовані за допомогою проекту [rq-exporter]

Dashboard ID `12196` підходить для візуалізації в Grafana або використовуйте
його [адаптацію][dashboard], який виводитиме лише метрики з guassp.

## Складання та налагодження проекту

Набір команд для швидкого локального налагодження

```bash
# Build
podman build -t guassp .

# Redis
podman run --rm -d -p 6379:6379 --name redis redis
# API
podman run --rm -d -p 5000:5000 --env-file .env --name guassp-api localhost/guassp:latest api
# Workers
podman run --rm -d --env-file .env --name guassp-worker-1 localhost/guassp:latest worker
podman run --rm -d --env-file .env --name guassp-worker-2 localhost/guassp:latest worker
# Exporter
podman run --rm -d -p 9726:9726 --env-file .env --name guassp-exporter localhost/guassp:latest exporter

# Check
curl 0.0.0.0:9726 -s | grep -v '^#'
curl 0.0.0.0:5000/tasks -s | jq
curl 0.0.0.0:5000/task -s -X POST -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq
```

Або запустимо локально, для цього потрібно встановити залежності

```bash
apt-get install -y libev-dev libevdev2
python -m venv .venv
./.venv/bin/activate
pip install requirements.txt
```

Або для простоти запустити застосунки через скрипт `guassp`

```bash
./guassp.sh api
./guassp.sh worker
./guassp.sh exporter
```

<!-- Посилання до файлів -->
[eng 🇬🇧]: ../README.md
[ua 🇺🇦]: README-ua.md
[rus 🇷🇺]: README-ru.md
[scheme]: scheme.drawio.png
[permissions]: permissions.drawio.png
[role-mapping]: role-mapping.png
[dashboard]: grafana-dashboard.json
[docker-compose.env]: docker-compose.env
[docker-compose.yml]: docker-compose.yml
[прикладу конфігурації Nginx]: nginx.conf
[sq-integration-taks]: sq-integration-taks.sh

<!-- Посилання до сторінок -->
[GitLab]: https://about.gitlab.com
[SonarQube]: https://www.sonarqube.org
[ALM]: https://docs.sonarqube.org/latest/analysis/gitlab-integration/#header-5
[jt]: https://docs.gitlab.com/ee/api/jobs.html#get-job-tokens-job
[flask]: https://github.com/pallets/flask
[bjoern]: https://github.com/jonashaag/bjoern
[python-gitlab]: https://github.com/python-gitlab/python-gitlab
[python-sonarqube-api]: https://github.com/shijl0925/python-sonarqube-api
[rq]: https://github.com/rq/rq
[rq-exporter]: https://github.com/mdawar/rq-exporter
[docker-compose]: https://docs.docker.com/compose/

<!-- Containers -->
[quay]: https://quay.io/repository/woozymasta/guassp
[dhub]: https://hub.docker.com/r/woozymasta/guassp
[ghcr]: https://github.com/WoozyMasta/guassp/pkgs/container/guassp
