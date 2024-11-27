
Anirem directament al reconeixement actiu per fer-ne via, fent un nmap directament i saltant-nos el reconeixement passiu:
```
┌──(polkali㉿kaliPol)-[~]
└─$ nmap -sC -sV -v 10.10.11.44
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-25 09:21 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Initiating Ping Scan at 09:21
Scanning 10.10.11.44 [4 ports]
Completed Ping Scan at 09:21, 2.20s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:21
Completed Parallel DNS resolution of 1 host. at 09:21, 0.06s elapsed
Initiating SYN Stealth Scan at 09:21
Scanning 10.10.11.44 [1000 ports]
Discovered open port 80/tcp on 10.10.11.44
Discovered open port 22/tcp on 10.10.11.44
Completed SYN Stealth Scan at 09:21, 3.37s elapsed (1000 total ports)
Initiating Service scan at 09:21
Scanning 2 services on 10.10.11.44
Completed Service scan at 09:21, 6.11s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.44.
Initiating NSE at 09:21
Completed NSE at 09:21, 1.43s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.18s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Nmap scan report for 10.10.11.44
Host is up (0.039s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://alert.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.00s elapsed
Initiating NSE at 09:21
Completed NSE at 09:21, 0.01s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.00 seconds
           Raw packets sent: 1171 (51.476KB) | Rcvd: 1002 (40.088KB)
                                                                             
```

Trobem dos ports oberts, accés a una web per el port 80 per http i a la que tinguem unes credencials ens podrem connectar per SSH ja que també té el port 22 obert. 

Abans de anar al port 80 per el navegador, farem un curl i un whatweb per veure que hi ha. Ho fem directe a la IP ja que encara no tenim el domini, i així potser el podem treure.

El curl ens indica que la pàgina web s'ha mogut de lloc i ens retorna un 301 de redirecció, però veiem també el nom del domini cosa que ens servirà per afegir-lo a l'`/etc/hosts`: 

```
curl http://10.10.11.44
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://alert.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at 10.10.11.44 Port 80</address>
</body></html>
```

Ara fem el whatweb:

```
┌──(polkali㉿kaliPol)-[~]
└─$ whatweb http://10.10.11.44
http://10.10.11.44 [301 Moved Permanently] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], RedirectLocation[http://alert.htb/], Title[301 Moved Permanently]
ERROR Opening: http://alert.htb/ - no address for alert.htb

```

Veiem que ens redirecciona a alert.htb, per tant ara l'afegirem al nostre fitxer `/etc/hosts` i veiem també, interessant, la versió del servidor apache que on corre la pàgina web.
```
sudo nano /etc/hosts

127.0.0.1       localhost
127.0.1.1       kali
10.10.11.38     chemistry.htb
10.10.11.32     sightless.htb
127.0.0.1       sightless.htb
10.10.11.44     alert.htb
```

Ara, amb el domini, tornarem a fer el curl i el whatweb:

Amb el curl veiem l'html de la pàgina web:
```
curl http://alert.htb  
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/style.css">
    <title>Alert - Markdown Viewer</title>
</head>
<body>
    <nav>
        <a href="index.php?page=alert">Markdown Viewer</a>
        <a href="index.php?page=contact">Contact Us</a>
        <a href="index.php?page=about">About Us</a>
        <a href="index.php?page=donate">Donate</a>
            </nav>
    <div class="container">
            </div>
    <footer>
        <p style="color: black;">© 2024 Alert. All rights reserved.</p>
    </footer>
</body>
</html>
```

I amb el whatweb a veure si podem treure alguna informació extra:
```
whatweb http://alert.htb
http://alert.htb [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], RedirectLocation[index.php?page=alert], Title[Alert - Markdown Viewer]
http://alert.htb/index.php?page=alert [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], Title[Alert - Markdown Viewer]
```

Veiem que ens redirigeix a un index.php, interessant, segurament hi haurà un formulari per on haurem d'intentar accedir amb XSS o SQL Injection o amb alguna vulnerabilitat d'algun software que no ens apareix amb el whatweb.