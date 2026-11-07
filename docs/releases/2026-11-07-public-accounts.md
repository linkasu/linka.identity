# I1 production release — 2026-11-07

I1 включён на https://api.identity.linka.su для `linka-type`, `linka-looks`, `linka-pictures`, `linka-plays`. Paper Board остаётся за policy gate. Это выпуск Identity backend, не завершение CRM consumer/V3 и mandatory-email клиентских миграций.

## Зафиксированный runtime

- Source: `9b5227d202011fed1223dea6d2bc8f87ff7d526f`, [PR 7](https://github.com/linkasu/linka.identity/pull/7).
- YC image: `cr.yandex/crp5051c3iheo6jgo8kt/linka-identity@sha256:73a60c8dd1cc2289c08b35d2e41e0e2f8f8a886741a7b9326189fb6f23540681`; образ собран только CI/GHCR.
- Active revision: `bbaeijht2rc3hpsma9je`, schema **2**, runtime principal `ajeesdb9vm232kicq06k`.
- `PUBLIC_ACCOUNT_ENABLED=true`, дневной лимит **200 rolling-24h**, темп **1/s**. Очередь до 48ч, OTP 10м от claim; uncertain delivery не повторяется автоматически.
- Worker timer `a1s3jtd9brg6ad14vtuv` восстановлен в `ACTIVE`; public worker path остаётся `404`.

## Проверки cutover

1. Обнаружен и остановлен повторный deploy старого main после CI feature-ветки. Workflow теперь только ручной, с точным SHA/tag и успешным CI, без автоматических миграций или rollback. Отрицательный normal-run на schema 1 остановился на `schema -check`, deploy был пропущен: [42359341950](https://github.com/linkasu/linka.identity/actions/runs/42359341950).
2. Native backup восстановлен в отдельную owned serverless-БД. Rehearsal тем же CI digest: 1→2, 22→29 таблиц, все 781 строка сохранены; 21 legacy data table совпала по хэшам, новые таблицы пусты. Для cold-compute временно включён 1 provisioned RCU по подтверждению пользователя; после проверки возвращён 0, временная БД удалена.
3. Timer приостановлен, maintenance revision `bbahhk7u12ohmmd5p6gd` запускалась без DB/KMS/SMTP/workers. У старого runtime `ajej1scalv5a8192b9u0` снят folder-level `ydb.editor`; его токен получил фактический `PermissionDenied`. Старый writer principal не возвращается после schema 2.
4. Claims outbox/privacy/email — 0. Финальный native backup **`etnups51g626ffluhm63`**, `READY`, TTL 168h, восстановлен в изолированный prefix. Все 791 строка и fingerprint совпали со снимком под ограждением.
5. Production migration из exact digest, отдельным deploy/migrator principal: schema 1→2, 22→29 таблиц. Все 21 legacy data table и их шифротексты неизменны; семь новых таблиц пусты до включения runtime.

Fingerprint до: `dd9c0aff0979c45a9e086008e659092079ccb539be97bcd8889f1fa7596e473a`.

Fingerprint после: `0965cf15bd0c3b7b2d4886b6b31a137a396f8fd49985505ff0d63b050d96fbbf`.

Подробные receipts содержат только metadata/row hashes, без расшифрованных контактов и секретов. 30 operator receipts с SHA-256 manifest сохранены отдельно на VPS: `/var/backups/linka-identity-i1/cutover-9b5227d-20261107`, доступ 0700/0600. Native backup остаётся в Managed YDB. Backup с TTL — не PITR.

## Resume и публичные gates

- [Core normal rollout 42373411405](https://github.com/linkasu/linka.identity/actions/runs/42373411405) и [I1 enable 42373610729](https://github.com/linkasu/linka.identity/actions/runs/42373610729) успешны; `/healthz`, `/readyz`, JWKS — 200.
- Account и private directory routes без нужного credential — 401. Unknown bootstrap — 201 без consent/metrics JWT; installation refresh не принимается как account credential.
- Для I1 созданы отдельные SMTP sender/API key (`yc.postbox.send`) и Lockbox secret. Дополнительная sender-role в папке Identity выдана только после явного подтверждения пользователя. STARTTLS/AUTH проверены, `MAIL/RCPT/DATA` не вызывались. SMTP key истекает **2027-02-05**; его необходимо ротировать до этого срока.
- Реальный email challenge и OTP-письмо **не создавались/не отправлялись**: пользователь отложил end-to-end delivery smoke. Это остаётся отдельным gate перед блокирующими app updates.
- Заявка Postbox `atdjdfucdvqi1b9huu3c` на 10000/day и 5/s остаётся `PENDING/PROCESSING`; runtime не повышает лимиты автоматически. Другие transactional-письма также используют общую provider quota.

Историческая рассылка остаётся выключенной. Покажи KMP не редактировался без canonical repository. Новый [runbook](../public-account-release.md) применяется к следующим schema changes; возврат schema-1 binary на текущую БД запрещён.
