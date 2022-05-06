<!-- omit in toc -->
# Guassp - GitLab User Access Synchronizer for SonarQube Projects

**Guassp** —
**Синхронизатор доступа пользователей GitLab для проектов SonarQube**

Проект предназначен для создания многопользовательской интеграции
[SonarQube][] и [GitLab][]. Видимость проекта и разрешения пользователей
будут установлены в SonarQube таким же образом, как разрешения для проекта в
GitLab.

> Этот документ доступен на языках: [eng 🇬🇧][], [ua 🇺🇦][], [rus 🇷🇺][]

* [Реализация](#реализация)
* [Компоненты](#компоненты)
* [Образы контейнеров](#образы-контейнеров)
* [Быстрый старт](#быстрый-старт)
* [Конфигурация](#конфигурация)
* [API](#api)
* [Пайплайн](#пайплайн)
* [Метрики](#метрики)
* [Сборка и отладка](#сборка-и-отладка)

## Реализация

Эта утилита состоит из **API** интерфейса, который принимает запросы на
обновление разрешений из конвейера GitLab CI, где все доверие [построено
вокруг][jt] `CI_JOB_TOKEN`, доверенные задачи добавляются в очередь
заданий RQ (Redis Queue). Задания обрабатываются бэкенд-воркерами **Worker**,
а для вывода статистики используется отдельный экспортер метрик prometheus.

![scheme][]

Права доступа выдаются по уровню доступа ролей SonarQube в соответствии
с имеющимися разрешениями у пользователей проекта в GitLab.  
Учитывается то, как GitLab реализует права доступа пользователей в
проекте, и пользователей из приглашенных групп, где уровни доступа
имитируются в соответствии с GitLab.

![permissions][]  
![role-mapping][]

* [Реализация](#реализация)
* [Компоненты](#компоненты)
* [Образы контейнеров](#образы-контейнеров)
* [Быстрый старт](#быстрый-старт)
* [Конфигурация](#конфигурация)
* [API](#api)
* [Пайплайн](#пайплайн)
* [Метрики](#метрики)
* [Сборка и отладка](#сборка-и-отладка)

## Компоненты

Проект реализован на [flask][], для WSGI применен [bjoern][], работа с
API GitLab происходит через [python-gitlab][], а SonarQube API через
[python-sonarqube-api][]. Для обработки очереди сообщений используется
[RQ][rq] чьи метрики отдает [rq-exporter][].

## Образы контейнеров

Вы можете получить образы из реестров:

* [`ghcr.io/woozymasta/guassp:latest`][ghcr]
* [`quay.io/woozymasta/guassp:latest`][quay]
* [`docker.io/woozymasta/guassp:latest`][dhub]

## Быстрый старт

Для быстрого старта можно использовать пример из [docker-compose][]:

1. [docker-compose.env][] - изменитe настройки в файле настроек окружения
2. [docker-compose.yml][] - выполните `docker-compose up -d`

## Конфигурация

Для запуска нужной утилиты передайте в контейнер или скрипт
`guassp.sh` аргумент:

* `worker` _(по умолчанию)_ - обработчик задач из очереди;
* `api` - API для управления заданиями;
* `exporter` - prometheus метрики;
* `all-in-one` - запуск `worker`, `api` и `exporter` сразу;
* `api-dev` - запуск API через flask dev сервер.

### Параметры приложения

* **`LISTEN_ADDRESS`**=`0.0.0.0` - Хост для публикации API;
* **`LISTEN_PORT`**=`5000` - Порт для публикации API;
* **`LOG_LEVEL`**=`INFO` - Уровень логирования;
* **`SECRET_KEY`**=`secret` - Секретный ключ;
* **`QUEUE_RESULT_TTL`**=`7200` - Время хранения результатов очереди;
* **`MORE_ACCURATE_SYNC`**=`true` - Поиск пользователей в SonarQube по
  электронной почте GitLab, иначе поиск происходит по имени
  пользователя. Это вызывает еще один запрос API для каждого
  пользователя, это более точно но медленнее в 2 раза.

### Параметры работы с GitLab

* **`GITLAB_URL`**=`https://gitlab.com` - Адрес сервера GitLab;
* **`GITLAB_TOKEN`** - Токен доступа к GitLab, должен иметь права на просмотр
  участников и их прав доступа для обслуживаемых проектов;
* **`GITLAB_SKIP_USERS`** - Список (разделенных запятой) ID пользователей
  которые будут пропущены при синхронизации.

### Параметры работы с SonarQube

* **`SONARQUBE_URL`** - Адрес сервера SonarQube;
* **`SONARQUBE_TOKEN`** - Токен доступа к SonarQube с административными
  привилегиями;
* **`SONARQUBE_ALM_KEY`** - Ключ [ALM][] (название) интеграции с GitLab;
* **`SONARQUBE_SKIP_GROUPS`** - список (разделенных запятой) групп
  которые будут пропущены при синхронизации.

### Параметры работы с Redis

* **`REDIS_URL`**=`redis://localhost:6379/0` - URL подключения к серверу Redis.

### Параметры экспортера метрик Prometheus

* **`EXPORTER_LISTEN_ADDRESS`**=`0.0.0.0` - Хост для публикации
  Prometeus метрик;
* **`EXPORTER_LISTEN_PORT`**=`9726` - Порт для публикации Prometeus метрик.

## API

### Регистрация задания

> POST **`/task`**
>
> ```json
> {"job_token": str}
> ```
>
> Headers: `JOB-TOKEN` or `Authorization: Bearer`

Нужно передать токен задачи в любом из вариантов:

```bash
curl -sL http://127.0.0.1:5000/task \
  -H "Content-Type: application/json" \
  -d '{"job_token": "'$CI_JOB_TOKEN'"}' | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "JOB-TOKEN: $CI_JOB_TOKEN" | jq

curl -sL http://127.0.0.1:5000/task -X POST \
  -H "Authorization: Bearer $CI_JOB_TOKEN" | jq
```

Токен задачи может быть передан заголовком `JOB-TOKEN` или
`Authorization: Bearer` или быть значением ключа `job_token` в JSON

### Очередь задач

> GET **`/tasks`**

```bash
curl -sL http://127.0.0.1:5000/tasks | jq
curl -sL http://127.0.0.1:5000/tasks | jq -er '.tasks | keys'
```

### Статус задачи

> GET **`/task/<job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e | jq
```

### Удаление задачи из очереди

> DELETE **`/task/<job_uuid>`**

```bash
curl -sL http://127.0.0.1:5000/task/8b155172-cfcf-4777-b9f4-bfce53b6eb0e \
  -X DELETE | jq
```

## Пайплайн

В пайплайне GitLab CI в первую очередь нужно убедиться, что настройка
[ALM][] сделана и относится к вашему проекту, после чего можно
отправлять задачу на синхронизацию в guassp. Вот теперь можно приступать
к анализу проекта.

Для публикации API Guassp за Nginx в рамках API SonarQube, смотрите
[пример конфигурации Nginx][]

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

Более объемный пример скрипта выполнения SonarQube в пайплайне вы можете
увидеть в файле [`sq-integration-taks.sh`][sq-integration-taks]

## Метрики

Метрики реализованы с помощью проекта [rq-exporter][]

Dashboard ID `12196` подходит для визуализации в Grafana или используйте
его [адаптацию][dashboard], который будет выводить только метрики из
guassp.

## Сборка и отладка

Набор команд для быстрой локальной отладки

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

Или запустим локально, для этого понадобятся установить зависимости

```bash
apt-get install -y libev-dev libevdev2
python -m venv .venv
./.venv/bin/activate
pip install requirements.txt
```

И для простоты запустить через скрипт `guassp`

```bash
./guassp.sh api
./guassp.sh worker
./guassp.sh exporter
```

<!-- Links files -->
[eng 🇬🇧]: ../README.md
[ua 🇺🇦]: README-ua.md
[rus 🇷🇺]: README-ru.md
[scheme]: scheme.drawio.png
[permissions]: permissions.drawio.png
[role-mapping]: role-mapping.png
[dashboard]: grafana-dashboard.json
[docker-compose.env]: docker-compose.env
[docker-compose.yml]: docker-compose.yml
[пример конфигурации Nginx]: nginx.conf
[sq-integration-taks]: sq-integration-taks.sh

<!-- Links web -->
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
