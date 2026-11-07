# Выпуск I1: schema 1 → 2

Статус: **локальная реализация, не разрешение применять миграцию**. Production Identity остаётся на schema 1; CRM schema 29 и выпуск Metrics не заменяют этот допуск.

## Совместимость и ограждение

| Режим / версия | БД | Поведение |
| --- | --- | --- |
| Прежний binary, schema 1 | 1 | Прежние private/V2 операции |
| Прежний binary | 2 | Readiness отклоняет версию; такой rollback запрещён |
| Новый binary, normal | 1 | Отказ до запуска workers / HTTP API |
| Новый binary, maintenance | 1 или 2 | Статический закрытый HTTP; без БД, KMS, SMTP и workers |
| Новый binary, normal, public accounts disabled | 2 | Совместимые private/V2 операции, без public account routes |
| Новый binary, normal, enabled и пустой signup allowlist | 2 | Новые OTP/доставка приостановлены; refresh/revoke/profile существующих сессий остаются |
| Новый binary, normal, разрешённые продукты | 2 | Только прошедшие отдельный capacity/policy gate продукты |

`IDENTITY_MAINTENANCE_MODE=true` используется только с новым проверенным CI-образом. Прежний образ этот режим не реализует. `/healthz` возвращает 200 с `mode=maintenance`, `/readyz` и все остальные операции — 503. На публичном Gateway `/internal/workers/tick` по-прежнему закрыт dummy-404.

Все писатели: public/private HTTP, private IAM tick, background outbox, privacy erasure, verification cleanup и account sender. Одна блокировка Gateway не останавливает background workers или прямые IAM-вызовы. Сначала приостановить timer и другие вызовы, переключить контейнер на maintenance и подтвердить прекращение старых инвокаций и leases. Если остановку прежних писателей доказать нельзя — **миграция заблокирована**; не принимать отсутствие HTTP-трафика за write fence.

## Порядок cutover

1. Проверить точный commit: unit/race, последовательные интеграционные тесты на отдельном YDB, OpenAPI/Gateway и полный smoke без реальных писем. Образы собирает только GitHub CI/GHCR; никаких локальных Docker builds.
2. Подготовить protected runtime configuration. Все прежние значения keyrings/registry/workloads сохранить. Directory reader — отдельная workload credential с `crm:product-directory:read` и явными products, не `product`/admin. Не включать mandatory-email обновления приложений.
3. Зафиксировать действующие image digest, Gateway spec, timer/invokers и schema version. Развернуть **тот же новый digest в maintenance**, приостановить timer/остальных вызывающих, подтвердить закрытие всех writers и drain. Возврат до миграции возможен только с подтверждённой schema 1.
4. Сделать native YDB backup под ограждением и дождаться успешного завершения конкретной операции; сохранить backup ID, исходную схему, timestamp, список таблиц/счётчики и digest, без адресов/секретов. Проверить restore в отдельный закрытый target path и сохранность baseline, не восстанавливать поверх живых таблиц. `yc ydb database backup/restore --help` описывает доступные CLI flags; целевые пути и полномочия требуют проверки перед выполнением.
5. Запустить `/usr/local/bin/schema` из **точного CI digest** выделенным migrator. Additive DDL идемпотентны; version 2 записывается последней. Ошибка до promotion оставляет version 1 с возможными пустыми новыми таблицами: maintenance сохраняется, тот же migrator можно повторить после устранения причины.
6. Проверить version 2, наличие семи новых таблиц и неизменность прежних данных/шифротекстов. Старые identities/installations не превращаются в подтверждённые public product accounts или consent.
7. Снять maintenance на том же digest с public accounts сначала выключенными; проверить private/V2 compatibility, readiness, JWKS и worker shield. Затем включить I1 только для разрешённого пилота после проверки SMTP/capacity. При ошибке после promotion возвращаться **в maintenance нового digest**, а не на schema-1 binary.
8. Реальную доставку и OTP проверить только по пользовательскому запросу на согласованный адрес: пользователь отложил этот smoke, он остаётся обязательным непройденным gate. Проверить unknown bootstrap, очередь/claim-time expiry, purpose separation, profile CAS, refresh replay, private directory/current permissions и privacy erasure. Вернуть timer и invokers только после проверки нового runtime; отложенный smoke не разрешает массовое включение или app-blocking updates.

Нативные backup/restore/rehearsal, прекращение production writers и новая runtime SMTP-конфигурация ещё **не выполнены**. Встроенный 7-дневный SYSTEM backup не является PITR или подтверждением rehearsal. Текущий `deploy-yc.yml` по-прежнему намеренно отказывается от `schema.Version != 1`; не заменять guard на `2` и не использовать старый automatic rollback. Для исполнения cutover нужен отдельно проверенный ручной workflow с явными maintenance/migrate/resume шагами и сохранением receipts.

## Временные данные и ключи

- Begin ставит OTP в очередь максимум на 48 часов без резерва дневной provider quota; исходные CreatedAt и queue deadline неизменны. Перед SMTP claim резервируются rolling-24h budget и 1/s, затем private verification и challenge атомарно получают 10-минутный срок кода от claim, не от Begin. Истечение кода или terminal queue expiry стирает code hash и encrypted code. При SMTP acceptance/uncertainty encrypted code стирается сразу, hash до истечения остаётся для проверки доставленного кода. Network/EOF/неопределённая доставка автоматически не повторяется.
- Только явный отрицательный SMTP 4xx с definite no-acceptance откладывает тот же job на 5 минут: encrypted code сохраняется, исходные CreatedAt/48-часовой deadline не меняются; следующий claim задаёт новое 10-минутное окно. `mailAttempts` монотонен; резерв квоты не возвращается даже при отрицательном результате.
- Challenge tombstones очищаются через 48 часов после expiry/cleanup; HMAC rate reservations сохраняют прежнее 48-часовое окно очистки. Это технические окна идемпотентности/защиты от сброса бюджета, не продление ожидания в очереди. Удаление установки не сбрасывает контактный/global budget.
- Refresh hashes, включая использованные, сохраняются до абсолютного 90-дневного срока family: раннее удаление уничтожило бы replay barrier. Истёкшие tokens/sessions очищаются ограниченными порциями; profile/verified account не удаляются из-за истечения сессии.
- Cleanup работает и из background worker, и из private IAM tick. Каждая порция ограничена; public accounts, consent/evidence и legal audit не удаляются этим техническим cleanup. Их общий legal retention остаётся отдельным решением владельца.
- Envelope/blind-index rotation guards учитывают новые challenges. OTP key ID нельзя менять при живых proofs; прежде остановить signup и дождаться истечения/очистки. Queued proofs могут потребовать ожидания до 48 часов, а не только 10 минут OTP. Не переиспользовать ID для другого key material.
- Directory refs/cursors живут 8 дней и находятся вне БД; retiring envelope keys надо сохранять минимум на этот срок после прекращения выдачи refs. DB guard не может найти уже выданные зашифрованные ссылки. При недоступности ключа проверка fail-closed, без разрешения отправки.
- Для retiring KMS/envelope keys учитывать также backup retention: DB guard не видит ссылки в резервных копиях. Не удалять ключ только потому, что live rows очищены; сначала подтвердить возможность restore всех ещё хранимых backup/artifacts.
- Для бессрочной локальной квитанции клиент сохраняет доверенный verification key вместе с ней. Истечение online session, ротация JWKS и недоступность сети не должны стирать локальные карточки или регистрацию. Квитанция не даёт online/metrics authority.

## Непройденные production gates

Работать внутри действующих Postbox quotas **200 сообщений и 1/s**, растягивая очередь. Runtime `PUBLIC_ACCOUNT_DAILY_LIMIT=200` ограничивает SMTP-попытки за rolling 24h и отдельно общую вместимость requested/delivering jobs. При заполнении новый Begin отклоняется с `429` и `Retry-After: 60`, а exact retry принятого запроса только опрашивает статус без списания, изменения времени или места в очереди. Contact anti-abuse 6/15m и resend 60s остаются. Лимит I1 не резервирует квоту всего облака: другие cloud SMTP users используют того же провайдера. При повышении дневного лимита отдельно проверить 48-часовую очередь, 10-минутный deadline от claim, sender throughput и бюджет YDB (в production 10 RCU / 5 GiB, unexpired replay hashes сохраняются).

Операторский статус запроса повышения квот YC: `atdjdfucdvqi1b9huu3c`, **PENDING/PROCESSING**, запрошены **10000 сообщений/день и 5/s**. Это не одобрение и не изменение runtime: остаются **200/1s**. Реальный letter/OTP smoke отложен пользователем и остаётся обязательным gate; очередь и запрос квот не разрешают массовое включение или блокирующие обновления приложений.

Рассылка по исторической базе остаётся выключенной (`false`) до отдельного решения после полного deployment. Покажи KMP остаётся blocked без canonical repository; Paper Board — за policy gate. Эта инструкция и успешные локальные тесты не снимают эти ограничения.
