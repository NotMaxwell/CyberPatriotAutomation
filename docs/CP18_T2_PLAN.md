# Implementation plan: CP18 Training Round 2 gaps

The gap list is in `docs/TASK_ANALYSIS.md` under "Gaps from the CP18 Training
Round 2 answer keys". This file assigns the work to seven independent packages
(A–G), split by file so that their branches merge cleanly, followed by one
package (H) that runs after the merge. Delete this file once all packages are
merged.

Answer-key text, extracted from the PDFs (the Windows ones by OCR):
`ReferenceMaterial/CP18_*.pdf`, `windowsAnswereKey.pdf`, `windowsServer.pdf`.

## Rules for every package

- Read `CLAUDE.md` and `docs/CLAUDE.md` first. They are the coding rules.
- Every write goes through `remediation::apply` (or an `*_ops` wrapper that uses
  it). Dry runs write nothing. Test the *decisions* (pure functions over text,
  tables, classifications), never `execute()` against the host. A test must
  never modify the machine it runs on.
- New files get the two-line licence header. Name tests after behaviour.
- Do **not** edit `README.md`, `docs/ARCHITECTURE.md`, `docs/TASK_ANALYSIS.md`,
  `rust/CHANGELOG.md` or the workspace version. The coordinator updates those
  after the merge. Put a short "Docs to update" section in your final report.
- Before finishing, from `rust/`: `cargo fmt`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace`. If you touched
  `crates/windows`, also `cargo clippy -p pinnacle-core -p pinnacle-windows -p
  pinnacle-cypat --all-targets --target x86_64-pc-windows-gnu -- -D warnings`.
- Commit on your worktree branch (not main), one or more commits, each message
  ending with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## A. Linux PAM and account hardening

Files: `linux/src/tasks/password_policy.rs`, `linux/src/pam_ops.rs`,
`linux/src/tasks/account_permissions.rs`, the `PASS_MIN_DAYS` entry in
`linux/src/knowledge.rs`.

1. **Remove `nullok`/`nullok_secure` from `pam_unix` lines in
   `/etc/pam.d/common-auth`** (and `common-password`, where it also appears).
   Add a pure fn in `pam_ops` (`strip_nullok(text) -> String`) plus a proved
   write. It must run **after** every `pam-auth-update` call in Password Policy,
   because the stock `unix` profile puts `nullok` back. Verify reads it back.
2. **`minlen` on the PAM line.** In `common-password`, ensure the `pam_pwquality`
   line carries `minlen=<the task's minlen>` and the `pam_unix` line carries
   `minlen=<same>`. Also ensure the `pam_unix` line carries `remember=<REMEMBER>`
   (pam_unix keeps its own history in `/etc/security/opasswd`; harmless alongside
   pam_pwhistory). Pure fn `set_module_arg(text, module, key, value)` that replaces
   an existing `key=` or appends one, touching only active lines for that module.
   Apply after `pam-auth-update`, like 1. Keep the existing order-safety checks
   and rollback intact.
3. **`PASS_MIN_DAYS` 7 → 2** in `knowledge.rs`, and `MIN_DAYS` 7 → 2 in
   `account_permissions.rs` (the Ubuntu 22 T2 key requires 1–3 inclusive). Update
   any tests that pin 7.
4. **Lock root when it has no password.** In Account Permissions, if root's shadow
   hash is empty (`user_ops::password_state("root") == Some("no password")`),
   lock it with `user_ops::lock`. Mint 21 T2 item 10. Never touch a root that
   already has a hash or is already locked.

## B. Linux user management: groups and hidden users

Files: `linux/src/tasks/user_management.rs`, `linux/src/user_ops.rs`, and
`core/src/readme_parser.rs` only if the parser test below fails.

1. **Apply `readme.group_requirements`.** After creating missing users and
   before removing surplus ones: for each requirement whose group is not one of
   `ADMIN_GROUPS` (those are handled by the admin logic already), create the
   group if it doesn't exist (new `user_ops::create_group(name, why)` using
   `groupadd`, through `remediation::apply`, reading `/etc/group` back), then
   `user_ops::add_to_group` for each member that exists. Additive only: never
   remove members a README didn't name. Validate group and user names (same rules
   as usernames) before passing them to a command. Dry run prints "Would create
   group / Would add". Count the results in `items_attempted`/`items_succeeded`.
   Add pure fn `group_actions(readme, existing_groups) -> Vec<GroupAction>` and
   test it.
2. **Hidden users.** An account with `1 <= uid < 1000` whose shell can log in, whose
   home directory is under `/home/`, and whose name is not in `SYSTEM_ACCOUNTS` is
   a person hiding below the human uid range (Mint 21 T2). Include such accounts in
   the authorisation diff (`unauthorised`) and the admin checks. Add the home
   directory to `Account` if it isn't already parsed from `/etc/passwd`. Test that
   `daemon`, `www-data`, `nobody`, `syslog` are never selected, and that
   `liv:x:999:999::/home/liv:/bin/bash` is.
3. **Parser check.** Add a test in `core/tests/readme_parser_tests.rs` for
   `Create a group called "spider" and add the following users to it: may, peni,
   stan, miguel` and the variant `Please add the user "mariya" to the "pioneers"
   group.` (the second may already pass). Fix the parser only if needed, and run
   the corpus snapshots (`cargo test -p pinnacle-core --test corpus_tests`); any
   snapshot diff must be explained in your report.

## C. Linux system hardening, packages, Mint updates, Apache

Files: `linux/src/tasks/security_hardening.rs`, `linux/src/file_ops.rs` (if
needed), `linux/src/knowledge.rs` (sysctl/sshd consts, `ALWAYS_PROHIBITED`,
`PACKAGE_IDS`), `linux/src/tasks/software_update.rs`.

1. **sysctl precedence.** Keep writing `SYSCTL_DROPIN`, then, for every sysctl
   setting, rewrite any *active* line for the same key with a different value in
   `/etc/sysctl.conf` and in every other `/etc/sysctl.d/*.conf` (follow symlinks;
   `99-sysctl.conf` is a symlink to `../sysctl.conf`), using `file_ops::set` on that
   path only when the key is present there. Don't add keys to files that lack them.
   Load with `sysctl --system` instead of `sysctl -p <dropin>`. Pure fn that, given
   `(path, text)` pairs and the settings, returns the list of conflicting
   `(path, key)` to fix. Test with `net.ipv4.ip_forward=1` in sysctl.conf.
2. **sshd precedence.** sshd keeps the *first* value it reads, and `Include
   /etc/ssh/sshd_config.d/*.conf` comes first in Ubuntu's main file, in lexical
   order. Rename `SSHD_DROPIN` to `/etc/ssh/sshd_config.d/00-pinnacle.conf`, and
   remove a legacy `99-pinnacle.conf` if present (through remediation). Then
   rewrite contrary active lines for managed keys in the main `sshd_config` and in
   other drop-ins, as in 1, so a checker grepping the main file sees
   `PermitRootLogin no`. Only touch `Match` blocks if you understand them; it's
   fine to skip lines inside a `Match` block and say so. Run `sshd -t` before
   reload and roll back on failure, if the current code doesn't already.
3. **Packages.** `ALWAYS_PROHIBITED` += `aisleriot` (game), `doona` (network
   fuzzer), `xprobe` (OS fingerprinting scanner). `PACKAGE_IDS` += `("X2Go",
   "x2goserver")`, `("X2GO Server", "x2goserver")`. Check the package lookup is
   case-insensitive. Extend the existing table tests.
4. **Mint automatic updates.** In Linux Software Updates, when the OS is Linux Mint
   (`ID=linuxmint` in `/etc/os-release`), enable Update Manager's "Apply updates
   automatically". **Verify the mechanism from the mintupdate source** before you
   implement it (github.com/linuxmint/mintupdate, the Automation preferences
   code). It's believed to be a flag file under `/var/lib/linuxmint/` plus the
   `mintupdate-automation-upgrade.timer`, but confirm the exact path and timer
   name. Proved write, dry-run safe, report-only if the mechanism isn't present on
   the image.
5. **Apache hardening.** If `/etc/apache2/` exists: `ServerSignature Off` and
   `ServerTokens Prod` in `/etc/apache2/conf-available/security.conf` via
   `file_ops::set` (`Style::Space`), and make sure `security.conf` is enabled
   (`a2enconf security` if `/etc/apache2/conf-enabled/security.conf` is missing).
   Reload apache2 only if it is active. Do nothing if Apache is not installed.

## D. Linux backdoor listener task (new task)

Files: new `linux/src/tasks/backdoor_listeners.rs`, `linux/src/tasks/mod.rs`,
one row in `linux/src/platform.rs`. Read-only use of
`tasks/scheduled_tasks_audit.rs` helpers (`CRON_LOCATIONS`, `scan_text`).

Scored on Ubuntu 22 T2 (`nc.traditional -l -p 1337`, launched from
`/etc/crontab`, 5 pts) and Mint 21 T2 (`python3 /usr/share/zod/kneelB4zod.py`
listening on 1337, 6 pts).

- New task `BackdoorListenersTask`, flag `--backdoors` (no short flag), label
  "Backdoor Listeners", Sequential, `with_readme!` (needs the README's critical
  services), `needs_readme: false`. Place the row just before
  `--software-management`. Windows gets no row.
- **Detect:** parse `ss -Htlnup` (pure parser over captured text) → (proto, local
  port, pid, process name). For each pid read `/proc/<pid>/exe` and
  `/proc/<pid>/cmdline`. A listener is a backdoor when either:
  (a) the executable's basename is a raw listener (`nc`, `nc.traditional`,
  `nc.openbsd`, `ncat`, `netcat`, `socat`); or
  (b) the executable is an interpreter (`python*`, `perl`, `ruby`, `php*`, `node`,
  `bash`, `sh`, `dash`) and the script path from cmdline is not owned by any dpkg
  package (`dpkg -S <path>` fails); or
  (c) the executable itself is not owned by any dpkg package and is outside
  `/opt/CyberPatriot`, `/snap`, `/usr/local/lib/node_modules`.
  Never select a process belonging to the scoring engine, to `sshd`, or to a unit
  the README marks critical (`readme_services::is_critical`). Never select by port
  number alone.
- **Act (real run only), per backdoor, each step through remediation:** kill the
  process (TERM, then KILL after 3 s; prove that `/proc/<pid>` is gone); delete the
  script or binary **only if it is not package-owned** (package-owned binaries
  such as `/usr/bin/nc.traditional` are left to Software Management's purge, so
  say that in the output); comment out every cron line, across `CRON_LOCATIONS`,
  that references the script/binary path (prefix `# disabled by pinnacle: `). If
  the process's systemd unit (from `/proc/<pid>/cgroup`) is a unit file under
  `/etc/systemd/system/` not owned by a package, stop, disable and mask it via
  `systemd_ops`.
- Record every finding in the ledger. Print a reminder that forensics questions
  may ask about the backdoor's path (Mint 21 T2 Forensics 1 did), so it should be
  answered first.
- Tests: the `ss` parser on captured output that includes `users:(("nc.traditional",pid=812,fd=3))`;
  the classifier for (a)/(b)/(c) and the exemptions; the cron line matcher; the
  `main.rs` table tests must still pass.

## E. Linux prohibited files: hacking tools and service data

Files: `linux/src/tasks/prohibited_media.rs` only (keep new tables in that file).

1. **Hacking-tool files.** Add a curated `HACKING_TOOL_NAMES` list (specific
   names only, no broad substrings like "patch", "crack" or "abel"): `pyrdp`,
   `brutus`, `mimikatz`, `metasploit`, `msfconsole`, `sqlmap`, `hydra`,
   `john-the-ripper`, `johnny`, `hashcat`, `aircrack`, `ettercap`, `nikto`,
   `responder`, `crackmapexec`, `impacket`, `ophcrack`, `wifite`, `beef-xss`,
   `routersploit`, `sherlock`, `doona`, `xprobe`, `zenmap`. Match against file
   names of archives (`zip`, `tar`, `gz`, `tgz`, `bz2`, `xz`, `7z`, `rar`), scripts
   (`py`, `pl`, `rb`, `sh`) and extensionless executables. Search the existing
   roots plus `/usr/games`, `/usr/local/games`, `/usr/local/bin`, `/usr/local/share`.
   Skip any file owned by a dpkg package (`dpkg -S`), and skip names the README
   lists as required software. Hacking tools are deleted on a real run without the
   README having to prohibit them (they're never legitimate, like
   `ALWAYS_PROHIBITED`). Media keeps its existing README gate.
2. **Critical service data is report-only.** Compute protected roots from the
   README's critical services: vsftpd → `anon_root` and `local_root` from
   `/etc/vsftpd.conf` plus `/srv/ftp`; samba → every `path =` in
   `/etc/samba/smb.conf`; apache2/nginx → `/var/www`. Files under a protected root
   are reported but never deleted (media *and* hacking tools), with the reason in
   the ledger (`remediation::record_skipped`). Mint 21 T2 penalty: "Important
   files removed from public FTP directories".
3. Tests: name matching, including that `patchnotes.zip` and `/usr/share/...`
   files are not flagged; the protected-root computation from sample
   `vsftpd.conf`/`smb.conf` text; that `/srv/ftp/Sales/override.txt` is never
   deleted when vsftpd is critical.

## F. Windows policy, registry, shares, Apache

Files: `windows/src/knowledge.rs` (the `REGISTRY_SETTINGS` region only),
`windows/src/tasks/password_policy.rs`, `windows/src/tasks/shared_folders_audit.rs`,
`windows/src/tasks/security_hardening.rs`.

1. **WinRM.** Add to `REGISTRY_SETTINGS`:
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service` `AllowUnencryptedTraffic`
   = 0, `AllowBasic` = 0; and `...\WinRM\Client` `AllowUnencryptedTraffic` = 0,
   `AllowBasic` = 0. Make sure the table tests still pass.
2. **Lockout threshold 1–4 is a penalty.** In `password_policy.rs`, treat
   `1..=4` as non-compliant (set it to `LOCKOUT_THRESHOLD`, which must be within
   5–50), in both `apply_lockout_policy` and the compliance display/verify. Extract
   the decision into a pure fn and test 0, 3, 5, 10 and 60.
3. **Domain controller shares.** When the machine is a domain controller
   (`HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions` `ProductType` =
   `LanmanNt`), also allow `NETLOGON` and `SYSVOL`. Pure fn
   `allowed_shares(is_dc) -> Vec<&str>`, tested. Non-DCs are unchanged.
4. **Apache `ServerSignature Off` / `ServerTokens Prod`.** In Windows Security
   Hardening, locate `httpd.conf` (`C:\Apache24\conf`, `C:\xampp\apache\conf`,
   `C:\Program Files\Apache*\conf`, `C:\Program Files (x86)\Apache*\conf`, and
   the `ImagePath` of any service whose name starts with `Apache`). Rewrite with a
   pure fn `harden_httpd_conf(text) -> String` that replaces active
   `ServerSignature`/`ServerTokens` lines (case-insensitive) or appends them, and
   leaves commented lines alone. Back up to `httpd.conf.pinnacle.bak` before the
   first write; prove the write by reading it back; restart the Apache service only
   if it was running. Report only if the file isn't writable.

## G. Windows software: prohibited list, folder installs, updates, file patterns

Files: `windows/src/knowledge.rs` (`ALWAYS_PROHIBITED` and `PACKAGE_IDS` only),
`windows/src/tasks/software_management.rs`, `windows/src/tasks/software_update.rs`,
`windows/src/tasks/prohibited_media.rs`.

1. **Prohibited list.** `ALWAYS_PROHIBITED` += `BitTorrent`, `uTorrent`,
   `Burp Suite`, `Nmap`, `Wireshark`. The existing README-required override must
   keep Wireshark when the README requires it (Windows 11 T2 penalises removing it),
   so add a test for exactly that.
2. **Folder-only and shortcut-only installs.** When a prohibited name matches no
   uninstall-registry entry, look for: a top-level directory in `C:\Program Files`
   or `C:\Program Files (x86)` whose name matches (`software_matching::matches`);
   and `.lnk` shortcuts on `C:\Users\*\Desktop`, `C:\Users\Public\Desktop` and the
   Start Menu folders whose name matches. Delete matched folders and shortcuts
   through remediation (prove absence afterwards). Never touch `Windows`, `Common
   Files`, `WindowsApps`, `Microsoft*`, `Windows Defender*`, `CyberPatriot`, or
   anything matching README-required software. Pure fn
   `folder_candidates(prohibited, dir_names, required) -> Vec<String>`, tested with
   `Jellyfin`, `Nmap`, `Burp Suite Community Edition`, and a required `Wireshark`.
3. **Update software Chocolatey didn't install.** `choco outdated` only sees
   choco-managed packages. For each installed app (from the uninstall registry
   inventory) that maps to a choco id in `PACKAGE_IDS` and isn't choco-managed,
   query the latest version (`choco search <id> --exact --limit-output`), compare
   it with the installed `DisplayVersion` (a pure version comparison, tested), and
   if older run `choco upgrade <id> -y --no-progress`. The official installer
   upgrades in place. Record the `InstallLocation` before and after. If it changed,
   report it in red as a probable penalty ("not installed at the default
   location"). README-required software goes first. Keep the existing choco flow
   for choco-managed packages.
4. **File patterns.** Add `brutus`, `pyrdp`, `darknet` to `HACKING_TOOL_PATTERNS`.
   Before flagging a file by pattern, skip it if its name matches any
   README-required software (`software_matching::matches`). Test that
   `brutus-aet2-darknet.zip` is flagged and that `Wireshark-4.2.exe` isn't when
   Wireshark is required.

## H. Answer-key tests (after A–G are merged)

Four new test files encoding each key item by item, in the style of
`crates/linux/tests/answer_key.rs` (doc comment quoting the item and points, one
test per automatable item, forensics items marked as for a human, a
"every automatable item has a test" check): Ubuntu 22 T2 and Mint 21 T2 in
`crates/linux/tests/`, Windows 11 T2 and Server 2019 T2 in `crates/windows/tests/`.
No READMEs were supplied, so build synthetic `ReadmeData` from what each key says
the README contains.
