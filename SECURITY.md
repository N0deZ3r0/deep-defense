# Security Policy

**English** · [Русский](#политика-безопасности)

## Supported versions

Fixes are published for the **latest release** only.

## Reporting a vulnerability

**Do not open a public issue.** Use a
[private security advisory](https://github.com/N0deZ3r0/deep-defense/security/advisories/new) —
only the maintainer can read it.

Please include the version, your Windows build, whether the VeraCrypt container layer was
on, and what an attacker gains: reading a vault without the password, learning something
about the password, or getting a password out of the process.

**Never attach a real vault file, and never send a real master password.** A vault built
with a throwaway password reproduces everything a real one would.

First reply within **48 hours**, a decision within a week. Accepted reports are credited in
the release notes unless you would rather not be.

## Scope

This program exists so that a file on disk does not give up passwords, and so that a file
holding two vaults does not admit it. In scope:

- Reading a vault, or any part of one, without the master password
- Anything that makes guessing the password cheaper than an Argon2id pass per guess
- A master password, key or entry reaching disk, the clipboard, a log line or a panic
  message in the clear
- Telling a file with a hidden vault from one without it, from the file alone
- Forging a change-log chain or a rollback record without the master key
- A recovery piece revealing anything about the password, or fewer than the threshold
  reconstructing it
- Any parser brought down by a crafted file — the vault file, an imported CSV or JSON, a
  wordlist, a recovery piece

If you are reviewing rather than reporting: [`docs/FORMAT.md`](docs/FORMAT.md)
specifies every byte this program writes, and
[`tools/reference_vault.py`](tools/reference_vault.py) is an independent
implementation of the vault format you can read in one sitting.

**Out of scope: the seventeen items in the README's Limits section.** They are known, argued
and deliberate. A measurement showing one of them is materially worse than described *is*
in scope — send it.

Also out of scope: an attacker who is already running code as you. Malware with your
privileges reads this process's memory, and no password manager survives that. It is named
in the README rather than defended against.

---

# Политика безопасности

**Русский** · [English](#security-policy)

## Поддерживаемые версии

Исправления выходят только для **последнего релиза**.

## Как сообщить об уязвимости

**Не создавайте публичную задачу.** Используйте
[приватный security advisory](https://github.com/N0deZ3r0/deep-defense/security/advisories/new) —
его видит только сопровождающий.

Приложите версию, сборку Windows, был ли включён слой контейнера VeraCrypt, и что именно
получает нападающий: чтение хранилища без пароля, сведения о самом пароле или пароль,
вытащенный из процесса.

**Никогда не прикладывайте настоящее хранилище и не присылайте настоящий мастер-пароль.**
Хранилище, созданное с одноразовым паролем, воспроизводит всё то же самое.

Первый ответ — в течение **48 часов**, решение — в течение недели. Принятые сообщения
упоминаются в описании релиза, если вы не предпочтёте обратное.

## Что в области действия

Чтение хранилища или его части без мастер-пароля; что угодно, удешевляющее перебор ниже
одного прохода Argon2id на попытку; попадание пароля, ключа или записи на диск, в буфер
обмена, в журнал или в сообщение об ошибке открытым текстом; способ отличить файл со
скрытым хранилищем от файла без него по самому файлу; подделка цепочки журнала изменений
или записи об откате без мастер-ключа; часть для восстановления, раскрывающая что-либо о
пароле, или сборка пароля из меньшего числа частей, чем порог; любой разборщик, который
удаётся уронить подделанным файлом.

**Вне области — семнадцать пунктов раздела «Известные ограничения» в README.** Они
известны, обоснованы и оставлены намеренно. Но измерение, показывающее, что какой-то из них
существенно хуже описанного, — в области действия, присылайте.

Также вне области — нападающий, уже выполняющий код от вашего имени. Вредоносная программа
с вашими правами читает память этого процесса насквозь, и этого не переживает ни один
менеджер паролей. Это названо в README, а не защищено.
