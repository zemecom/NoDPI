# AGENTS

## Назначение проекта

NoDPI - локальный HTTP/HTTPS proxy для обхода DPI через модификацию TLS ClientHello.
Основная точка входа: `src/main.py`.
Основной код приложения расположен в пакете `src/nodpi/`.

## Текущая структура

- `src/main.py` - совместимый entrypoint и re-export основных сущностей.
- `src/nodpi/app.py` - bootstrap приложения.
- `src/nodpi/proxy.py` - orchestration proxy-соединений и обработка ошибок.
- `src/nodpi/dns.py` - system DNS retry и fallback через DNS-over-TCP.
- `src/nodpi/runtime_ui.py` - banner, live statistics, update check.
- `src/nodpi/config.py` - CLI, JSON config, env override, автоподхват `nodpi.json`.
- `src/nodpi/blacklists.py` - blacklist managers.
- `src/nodpi/platform.py` - Windows tray и autostart logic.
- `tests/test_dns_resolver.py` - регрессии по DNS и CONNECT.
- `tests/test_config_loader.py` - конфиг, env и автоподхват `nodpi.json`.

## Как запускать

- Обычный запуск: `python3 src/main.py`
- Явный конфиг: `python3 src/main.py --config ./nodpi.json`
- Боевой локальный конфиг: `nodpi.json`
- Шаблон конфига: `nodpi.example.json`
- Через Makefile: `make up`

Если существует `./nodpi.json`, он подхватывается автоматически без `--config`.

## Git remotes

- `origin` - основной remote, указывает на форк: `https://github.com/zemecom/NoDPI.git`
- `upstream` - исходный проект: `https://github.com/GVCoder09/NoDPI.git`
- `remote.pushDefault=origin`, поэтому обычный `git push` должен идти в форк по умолчанию
- `main` отслеживает `origin/main`

Для подтягивания изменений из исходного проекта использовать:

```bash
git fetch upstream
git switch main
git merge upstream/main
git push origin main
```

Если нужна линейная история, допустим такой вариант:

```bash
git fetch upstream
git switch main
git rebase upstream/main
git push origin main
```

Предпочтение по умолчанию:

- пушить только в `origin`
- обновления брать из `upstream`
- не пушить изменения напрямую в `upstream`

## Проверки перед завершением работы

Всегда запускать минимум:

```bash
python3 -m py_compile src/main.py src/nodpi/*.py tests/*.py
python3 -m unittest discover -s tests -v
```

Локально предпочтительно пользоваться Makefile:

```bash
make install-deps
make compile
make test
make ci-check
make install-hooks
```

`make install-hooks` подключает версионируемый `pre-commit`, который перед каждым `git commit` запускает локальные CI-проверки.
`make install-deps` устанавливает dev-зависимости из `requirements-dev.txt`.
Для `make lint`, `make ci-check` и `pre-commit` нужен установленный набор dev-зависимостей.

Если меняются импорты, конфиг или DNS-path, эти проверки обязательны.

## Правила изменений

- Не возвращать монолитный код обратно в `src/main.py`.
- Новую низкоуровневую сетевую логику выносить в отдельные модули, а не смешивать с UI.
- В `ConnectionHandler` допустимы orchestration и compatibility wrappers, но не крупные протокольные реализации.
- Для DNS-ошибок сохранять честный `reason` и отдельный `system_reason`, не подменять финальную причину промежуточной.
- Не коммитить локальный runtime-конфиг `nodpi.json`.
- При изменении CLI или config loader обновлять README и тесты.

## Что важно не сломать

- `CONNECT` не должен отвечать generic `500` при временных DNS-сбоях.
- Fallback DNS-over-TCP должен оставаться рабочим для проблемных доменов вроде YouTube.
- Автоподхват `nodpi.json` должен сохраняться.
- Старые импорты из `src.main` должны продолжать работать.

## Предпочтения по дальнейшему рефакторингу

- Следующий кандидат на вынос: HTTP/auth/error-response слой из `src/nodpi/proxy.py`.
- После сетевого слоя можно дробить `platform.py`, если Windows tray будет расти.
- Если добавляется новая конфигурация, сначала расширять `ProxyConfig`, потом `ConfigLoader`, потом тесты.
