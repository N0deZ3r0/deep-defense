# Contributing

**English** · [Русский](#участие-в-разработке)

## The one rule

No new cryptography. Everything here is assembled from primitives that have been studied
for years — Argon2id, AES-256-GCM, XChaCha20-Poly1305, HKDF, Shamir's scheme over
GF(2⁸) — and the only thing this project claims is that the assembly is honest. A clever
cipher written for this repository would be the weakest thing in it, and no test can find
what is wrong with one.

Novel *construction* from proven parts is welcome: the cascade, the deniable slots and the
rollback record all are that. Novel *primitives* are not.

The second rule is smaller and follows from the first: a change to how something is sealed,
derived or refused comes with a test that fails without it.

A third, for the known-answer tests in `src/vectors.rs`: if one fails, do not update the
expected value until you know which implementation is wrong. Those values come from
`tools/reference_vault.py`, which is built on different libraries precisely so that the
two can disagree. A change to the format means changing `docs/FORMAT.md`, the reference
and the Rust together, and saying so.

## Before you file a bug

Read the **Limits** section of the README. Seventeen things are listed there as knowingly
open, with the reason for each. If what you found is one of them, it is not a bug — though
a measurement showing one of them is *worse* than described is very welcome.

If it is a vulnerability rather than a bug, do not open an issue at all: see
[SECURITY.md](SECURITY.md).

## Running it

```bash
cargo test            # 339 tests, about four minutes
cargo build --release
```

Or `build.ps1`, which locates the toolchain, builds and records the fingerprint. Rust 1.98,
target `x86_64-pc-windows-gnu` — the README says why, and what to install for it.

If your clone sits in a path containing a space, set `CARGO_TARGET_DIR` to somewhere
without one before running cargo directly. `dlltool` does not quote the temporary file it
hands the assembler, and the failure reads like a missing object file rather than a path
problem. `build.ps1` handles it for you.

The slowest tests are the vault ones, because each creates a real vault and each unlock is
a real Argon2id pass at the floor cost. That is the point of them; they are slow for the
same reason the program is safe.

## Pull requests

- **One change per pull request.** A change that fixes a defect *and* renames files is hard
  to review and hard to revert.
- **Say what you measured.** "This looks safer" is not a reason; a failing test, a
  benchmark, or a byte-level comparison is.
- **Match the surrounding code.** The comment density here is deliberate: a comment records
  *why* something is the way it is, usually with the alternative that was rejected and
  what was wrong with it. Code that merely restates itself in English is worse than none.
- **Never print a secret.** Types holding passwords or keys have hand-written `Debug`
  implementations that redact. If you add one, do the same — a derived `Debug` will put a
  master password in a panic message eventually.
- **Both languages or neither.** Every user-visible string lives in `src/i18n.rs` in English
  and Russian, and a test fails if the two disagree about how many substitutions a template
  takes.
- **Every control needs a name.** The field helpers take the spoken name as a required
  argument and a test walks the accessibility tree; a control announced as nothing is a
  defect nobody sighted will ever notice.

## Language

Issues and pull requests in **English or Russian** are equally welcome.

---

# Участие в разработке

[English](#contributing) · **Русский**

## Единственное правило

Никакой новой криптографии. Всё здесь собрано из примитивов, которые изучают годами, —
Argon2id, AES-256-GCM, XChaCha20-Poly1305, HKDF, схема Шамира над GF(2⁸), — и
единственное, что проект утверждает, это что сборка честная. Хитрый шифр, написанный
специально для этого репозитория, оказался бы самым слабым местом в нём, и ни один тест не
покажет, что с ним не так.

Новая **конструкция** из проверенных частей приветствуется: каскад, неотличимые слоты и
запись об откате — ровно это. Новые **примитивы** — нет.

Второе правило меньше и следует из первого: изменение в том, как что-то запечатывается,
выводится или отвергается, приходит вместе с тестом, который без него падает.

## Прежде чем заводить баг

Прочитайте раздел **«Известные ограничения»** в README. Там семнадцать пунктов, заведомо
оставленных открытыми, и причина по каждому. Если вы нашли один из них — это не баг. А вот
измерение, показывающее, что какой-то из них *хуже*, чем описано, очень пригодится.

Если это уязвимость, а не баг, — не создавайте задачу вовсе, см. [SECURITY.md](SECURITY.md).

## Как запустить

```bash
cargo test            # 339 тестов, около четырёх минут
cargo build --release
```

Или `build.ps1` — он находит инструментарий, собирает и записывает отпечаток. Rust 1.98,
цель `x86_64-pc-windows-gnu`; в README сказано, почему именно она и что для неё поставить.

Если клон лежит в пути с пробелом, задайте `CARGO_TARGET_DIR` на путь без пробела,
прежде чем звать cargo напрямую. `dlltool` не заключает в кавычки временный файл,
и ошибка выглядит как пропавший объектный файл, а не как беда с путём. `build.ps1`
делает это за вас.

Самые медленные тесты — про хранилище: каждый создаёт настоящее хранилище, и каждое
открытие — настоящий проход Argon2id по нижней границе стоимости. В этом и смысл: они
медленные ровно по той причине, по которой программа безопасна.

## Пул-реквесты

- **Одно изменение — один пул-реквест.**
- **Пишите, что измеряли.** «Так безопаснее» — не довод; падающий тест, замер или побайтовое
  сравнение — довод.
- **Держитесь стиля вокруг.** Плотность комментариев здесь намеренная: комментарий
  фиксирует, *почему* сделано именно так, обычно вместе с отвергнутой альтернативой и тем,
  чем она плоха. Комментарий, пересказывающий код по-английски, хуже его отсутствия.
- **Никогда не печатайте секрет.** У типов с паролями и ключами написаны свои реализации
  `Debug`, которые вымарывают значения. Добавляете такой тип — сделайте так же: выведенный
  `Debug` рано или поздно положит мастер-пароль в сообщение об ошибке.
- **Оба языка или ни одного.** Каждая видимая строка живёт в `src/i18n.rs` на английском и
  русском, и тест падает, если в шаблонах разное число подстановок.
- **У каждого элемента должно быть имя.** Помощники полей принимают произносимое имя
  обязательным аргументом, а тест обходит дерево доступности: элемент, который диктор
  читает как ничто, — дефект, которого никто зрячий не заметит.

## Язык

Задачи и пул-реквесты на **русском или английском** одинаково приветствуются.
