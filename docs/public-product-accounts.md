# Public product accounts: контракт I1 и допуск

Статус: локальная, невыпущенная реализация в работе. Наличие этого документа или gateway template не означает deployment и допуск клиентов. Принятый общий scope — tracking `linkasu/crm#1`, Identity `linkasu/linka.identity#5`. Совместимость, ограждение, очистка и оставшиеся gates описаны в [runbook schema 1→2](public-account-release.md).

## Interface модуля

| Метод / путь | Назначение |
| --- | --- |
| `POST /v1/public/email/challenges` | Registered product, purpose `product_registration`, request UUID, email, client nonce, self/representative; installation refresh capability в Authorization |
| `POST /v1/public/email/challenges/{id}/verify` | Code, nonce и product в том же installation context |
| `POST /v1/public/account-sessions/refresh` | Вращаемая capability устройства; replay отзывает её session family |
| `POST /v1/public/account-sessions/revoke` | Текущая онлайн-сессия; локальные данные не стираются |
| `PUT /v1/public/account-profile` | Versioned заявленная роль и необязательный грубый регион; без диагноза и данных ребёнка |
| `POST /v1/internal/product-directory/query` | Private workload `crm:product-directory:read`, только разрешённый product; минимальные контакты страницами |
| `POST /v1/internal/product-directory/check` | Тот же private workload: текущая проверка выданных contact references, не разрешение на рассылку |

Сервер выбирает audiences/scopes и проверяет закрытый product allowlist. Workload credentials не попадают в приложение. Existing anonymous installation routes/V2 остаются совместимыми; сами по себе они не подтверждают регистрацию аккаунта.

### HTTP и credentials

- Bootstrap: `POST /v1/public/installations` с `preference: unknown` создаёт installation без consent, suppression и Metrics JWT (`metrics_token: null`). `policy_version` и `recorded_at` остаются обязательными; `unknown` не означает согласие. Installation refresh JWT позволяет начать OTP, но не заменяет account JWT.
- Begin принимает строго `{request_id, product_id, email, purpose, client_nonce, holder_role}`: request UUIDv4, purpose `product_registration`, nonce — 32 случайных байта в canonical unpadded base64url (43 символа), holder role `self`/`representative`. Bearer — installation refresh JWT. Ответ `202`: `{contract_version: 1, challenge_id, status: pending, expires_at, resend_after}`; это не подтверждение доставки или наличия аккаунта. Exact retry возвращает challenge; изменённое тело с прежним request ID — `409`.
- Verify с тем же installation bearer принимает `{product_id, code, client_nonce}`, code — строка из шести цифр. Ответ `200` (как и refresh): `{contract_version: 1, product, account_key, installation_key, account_profile, account_token, refresh_token, refresh_expires_at, registration_receipt, metrics_token}`. Сейчас `metrics_token` всегда `null`, и это не мешает регистрации. `account_token` — `{access_token, token_type: Bearer, expires_at}`, отдельный короткоживущий account JWT, не Metrics JWT.
- Refresh требует **account refresh capability**, opaque canonical base64url, не installation JWT и не account JWT; тело строго `{}`. Сохранять новую capability атомарно вместо прежней. Revoke требует **account JWT** и `{}`, ответ `{revoked: true}`. Registration receipt подписана для локального доступа, никогда не передаётся как online bearer; account/installation/metrics/receipt purposes невзаимозаменяемы.
- Profile требует account JWT и `{version, holder_role, country?, region?}`. `version` — ожидаемая текущая версия (CAS); конфликт даёт `409`, успех возвращает полный `{product, account_key, version, holder_role, country, region, updated_at}` с новой версией. Страна/регион — только заявленные коды вида `RU`/`RU-MOW`, регион должен соответствовать стране; omission/пустая строка очищают значение. Нет email, произвольного адреса или вывода географии из IP.
- Public account endpoints требуют один `Authorization`, `application/json`, non-null object до 4 KiB, без query и неизвестных полей; все ответы `Cache-Control: no-store`. Ошибки JSON `{error}`: `400 invalid_request`/`challenge_rejected`, `401 invalid_credential`, `403 forbidden`/`forbidden_origin`, `409 conflict`, `429 rate_limited` с целочисленным `Retry-After` в секундах, `503 account_unavailable`.
- Public `OPTIONS` для каждого public route передаётся приложению. Только точные origins из `PUBLIC_INSTALLATION_ALLOWED_ORIGINS`; разрешены `POST, PUT, OPTIONS` и headers `Authorization, Content-Type`. Нет cookies/`Access-Control-Allow-Credentials`. Native clients не отправляют Origin. Directory не использует public CORS и не принимает public account credentials.
- Directory query: `{product_id?, cursor?, limit?}`; product можно опустить только у single-product workload, limit 0/omission = 25, максимум 50. Ответ `{contract_version: 1, product, entries, next_cursor?, data_as_of}`; opaque cursor привязан к продукту. Entry: `{account_key, contact_reference, email, origin, verified_at, holder_role, country, region, version, telemetry_preference, permissions}`. Email раскрывается только этому scoped workload; `account_key` — alias directory/telemetry audience, не public account audience.
- Directory check: `{product_id?, references}` (1..50 уникальных contact references), ответ `{contract_version: 1, product, results, checked_at}`. Каждый result содержит `contact_reference`, `state: active|inactive|unknown`; при active — `account_key`, `version`, `permissions`, иначе `reason`. Permissions по `news/research/service`: `status: unknown|granted|withdrawn` и evidence/policy/time при наличии; `unknown` не даёт права отправки. Query/check — JSON object до 64 KiB, без query и неизвестных полей; ошибки `400`, `401`, `403`, `409`, `503 directory_unavailable`.

### Environment и пауза регистрации

`.env.example` оставляет `PUBLIC_ACCOUNT_ENABLED=false`, `PUBLIC_ACCOUNT_PRODUCTS` и секреты пустыми. При включении нужны зарегистрированные `PRODUCTS_JSON`/`PUBLIC_INSTALLATION_PRODUCTS`, `TOKEN_MAX_TTL >= 5m`, утверждённый `PUBLIC_ACCOUNT_POLICY_VERSION`, `PUBLIC_ACCOUNT_OTP_KEY_ID` (default `otp-v1`), независимый `PUBLIC_ACCOUNT_OTP_KEY_BASE64` (canonical standard base64, 32..128 байт), `PUBLIC_ACCOUNT_SMTP_ADDR` (`host:port`), `PUBLIC_ACCOUNT_SMTP_USER`, `PUBLIC_ACCOUNT_SMTP_PASSWORD`, `PUBLIC_ACCOUNT_SMTP_FROM` (bare email). Реальные секреты — только из защищённого хранилища.

`PUBLIC_ACCOUNT_PRODUCTS` — разделённый `;` signup allowlist, подмножество `PUBLIC_INSTALLATION_PRODUCTS`. Пустой список при включённом broker останавливает begin/verify, но не refresh/revoke/profile уже созданных сессий. `PUBLIC_ACCOUNT_ENABLED=false` выключает account broker целиком; это не эквивалент паузы signup. `PUBLIC_ACCOUNT_DAILY_LIMIT` (default 200, диапазон 1..10000) — durable budget, не доказательство мощности. Наблюдаемые provider quotas 200 писем и 1/s не являются capacity approval. Эти значения не включают маркетинг или историческую рассылку.

## Матрица локального доступа

| Состояние | Общение без сети | Онлайн | Telemetry |
| --- | --- | --- | --- |
| registration_required / challenge_pending | Нет; прежние данные сохранены | Только bounded registration/recovery | Нет |
| registered + проверенная квитанция | Да | Только с живой сессией | Только с отдельным consent и подходящим credential |
| session_expired | Да, по квитанции | Refresh или повторный OTP | Отправка только после восстановления полномочий |
| secure storage failure | Явное восстановление без удаления данных | Повторная аутентификация | Нет plaintext fallback |

Квитанция — свидетельство, не онлайн-полномочие ([ADR 0001](adr/0001-offline-registration-receipt.md)). Не собирать письма/контент речи в telemetry. `metrics_token` может отсутствовать до готовности соответствующего transport; account access не подменяет его.

## Инварианты реализации

- OTP: срок 10 минут, не более пяти проверяемых неверных попыток, resend не чаще 60 секунд. Product/contact/global budgets сохраняются сервером; смена installation UUID не отменяет contact/global budget. Generic response не сообщает о существовании аккаунта.
- Purpose/product/installation/nonce/email binding перепроверяются в одной serializable-транзакции с registration, linkage, выдачей device session и consumption. KMS, случайные capabilities и подпись готовятся вне retry. Ошибка audit/session write не оставляет частично зарегистрированный аккаунт.
- Requested/claimed delivery, successful delivery и подтверждение кода — разные факты. SMTP acceptance не означает verified. Неопределённый результат доставки не запускает автоматический повтор SMTP; поздний sender не возвращает consumed/cancelled challenge в active.
- Повторное подтверждение того же email в продукте возвращает прежний account; чужой product/installation не может присвоить proof. Исправление email создаёт новый flow; поздний callback старого flow не меняет текущую регистрацию.
- Refresh: device-scoped rotating capability; replay закрывает family, не удаляет офлайн-данные. Все онлайн-операции проверяют активность session/account, одной проверки подписи недостаточно.
- Private CRM directory выдаёт только разрешённые продукты, product alias, защищённый контакт и минимальные признаки. Недельная копия не является текущим полномочием отправки. Withdrawal/delete и telemetry opt-out различны; invalidation должна охватывать account и installation aliases.

## Все писатели и совместимость

Затрагиваются существующие private email begin/attest/complete/cleanup, registration/deduplication/linkInstallation, public installation/preference, privacy erasure и worker claims. Новые public challenge/session/profile writers должны использовать те же typed records/transaction helpers, без альтернативной записи аккаунтов.

Порядок shared writes: challenge/лимиты → verification → blind indexes → person/account/installation → product registration/session → consume/audit. Внешние эффекты запрещены внутри SDK retry. Неверный OTP должен сохранить attempts, но не identity/session writes.

Новая durable схема требует отдельной совместимости: старый binary на новой версии отказывается Ready; новый binary до миграции также fail-closed. Existing identity/installation rows не превращаются автоматически в public product registration или consent. Перед продвижением версии нужны rehearsal, ограждение всех HTTP/workload/worker writers и запрет автоматического rollback на несовместимый binary; текущий deployment workflow допускает только schema 1 и не является готовым rollout для новой схемы.

## Acceptance до включения клиентов

1. Неверный purpose/product/nonce/code, expiry, concurrent verify и refresh replay отвергаются; failure injection откатывает registration+session+consume вместе.
2. Реальный изолированный YDB подтверждает rollback, deduplication, recovery и privacy writers; fake-only проверки не являются durable evidence.
3. Разные audiences не взаимозаменяемы: account access / installation refresh / metrics JWT / квитанция. В payload нет email, global person ID, key material.
4. Установка обновления не стирает данные; до OTP gate закрыт, после OTP локальная работа сохраняется без сети и при истёкшей online-сессии. Проверить secure storage failure и stale responses на каждой платформе.
5. Проверены реальный sender, provider quotas и общий темп. Текущие наблюдаемые Postbox quotas 200 писем и 1/s не являются подтверждением достаточной мощности для массового rollout. Marketing campaigns и первая историческая рассылка остаются отдельно выключенными по решению пользователя.
6. Для Paper Board сохраняется policy gate, Покажи KMP — за подтверждением canonical repo. Не выпускать блокирующие обновления приложений до работающего I1 и обязательных проверок.
