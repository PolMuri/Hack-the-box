Primer de tot fem un nmap per veure els ports que hi ha oberts a la màquina víctima:

```
──(polkali㉿kaliPol)-[~]
└─$ nmap -sC -sV -v 10.10.11.38         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-04 19:09 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
Initiating NSE at 19:09
Completed NSE at 19:09, 0.00s elapsed
Initiating NSE at 19:09
Completed NSE at 19:09, 0.01s elapsed
Initiating Ping Scan at 19:09
Scanning 10.10.11.38 [2 ports]
Completed Ping Scan at 19:09, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:09
Completed Parallel DNS resolution of 1 host. at 19:09, 0.01s elapsed
Initiating Connect Scan at 19:09
Scanning 10.10.11.38 [1000 ports]
Discovered open port 22/tcp on 10.10.11.38
Discovered open port 5000/tcp on 10.10.11.38
Completed Connect Scan at 19:09, 2.11s elapsed (1000 total ports)
Initiating Service scan at 19:09
Scanning 2 services on 10.10.11.38
Completed Service scan at 19:10, 95.12s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.38.
Initiating NSE at 19:10
Completed NSE at 19:10, 1.63s elapsed
Initiating NSE at 19:10
Completed NSE at 19:10, 1.10s elapsed
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Nmap scan report for 10.10.11.38
Host is up (0.060s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Mon, 04 Nov 2024 18:09:13 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=11/4%Time=67290DC5%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Mon,\x2004\x20Nov\x202024\x2018:09:13\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x2
SF:0\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=
SF:\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">
SF:Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>W
SF:elcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x
SF:20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20In
SF:formation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20c
SF:ontained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class
SF:=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center>
SF:<a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Re
SF:gister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x
SF:20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x2
SF:0\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Cont
SF:ent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\
SF:n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20r
SF:esponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400<
SF:/p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20v
SF:ersion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Initiating NSE at 19:10
Completed NSE at 19:10, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.83 seconds

```

Ens trobem amb el port 22 obert per SSH i el port 5000 hi ha Werkzeug que és una completa biblioteca d'aplicacions web WSGI, hi podem accedir a través d'un navegador, i ho sabem perquè ens dona un 200 per HTTP. Va començar com una simple col·lecció de diverses utilitats per a aplicacions WSGI i s'ha convertit en una de les biblioteques d'utilitats WSGI més avançades.

Ara provarem d'accedir a la pàgina pel port 5000 i ens trobem això (ara afegeixo també chemistry.htb al fitxer /etc/hosts):

![[Pasted image 20241104191705.png]]

Veiem que hi ha un analitzador CIF, una eina especialitzada destinada a l'anàlisi dels fitxers CIF. Sembla que aquesta eina analítica dóna funcionalitats que faciliten l'avaluació de la integritat i la qualitat de les dades.

Com que ens podem registrar o bé iniciar sessió, provarem de crear-nos un compte.

![[Pasted image 20241104192354.png]]

Un cop registrats, tenim una pàgina que ens permet pujar fitxers CIF:

![[Pasted image 20241104193206.png]]

Com que no sé que són els fitxers CIF he buscat per internet hi he trobat que són Arxiu d'Informació Cristalogràfica i és el format estàndard per facilitar l'intercanvi de dades cristal·logràfiques i va ser publicat per primera vegada per Hall, Allen i Brown el 1991.

El seu ús principal: Unió Internacional de Cristal·lografia (IUCr) ha triat el format de fitxer CIF com a estàndard per emmagatzemar i compartir informació cristal·logràfica. 

Pel que veiem, sembla que haurem de trobar la manera i forma de modificar i explotar fitxers CIF per poder obtenir una reverse shell. 

Al propi dashboard hi ha un exemple a descarregar d'un fitxer CIF:

![[Pasted image 20241104193303.png]]

Després de no saber ben bé què fer amb aquest fitxer CIF, he pensat que podria buscar patrons que resultin en algun exploit dels fitxers CIF, d'aquest en concret.
