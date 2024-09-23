Anirem directe al reconeixement actiu, fent un nmap directament i saltant-nos el reconeixement passiu:
```
┌──(polkali㉿kaliPol)-[~]
└─$ nmap -sC -sV -v 10.10.11.32           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-22 19:48 CEST
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 19:48
Completed NSE at 19:48, 0.00s elapsed
Initiating NSE at 19:48
Completed NSE at 19:48, 0.00s elapsed
Initiating NSE at 19:48
Completed NSE at 19:48, 0.00s elapsed
Initiating Ping Scan at 19:48
Scanning 10.10.11.32 [2 ports]
Completed Ping Scan at 19:48, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 19:48
Completed Parallel DNS resolution of 1 host. at 19:48, 0.01s elapsed
Initiating Connect Scan at 19:48
Scanning 10.10.11.32 [1000 ports]
Discovered open port 80/tcp on 10.10.11.32
Discovered open port 21/tcp on 10.10.11.32
Discovered open port 22/tcp on 10.10.11.32
Discovered open port 8081/tcp on 10.10.11.32
Completed Connect Scan at 19:48, 3.49s elapsed (1000 total ports)
Initiating Service scan at 19:48
Scanning 4 services on 10.10.11.32
Completed Service scan at 19:48, 28.68s elapsed (4 services on 1 host)
NSE: Script scanning 10.10.11.32.
Initiating NSE at 19:48
Completed NSE at 19:48, 10.66s elapsed
Initiating NSE at 19:48
Completed NSE at 19:49, 28.68s elapsed
Initiating NSE at 19:49
Completed NSE at 19:49, 0.01s elapsed
Nmap scan report for 10.10.11.32
Host is up (0.044s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
8081/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Froxlor
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

```

Trobem quatre ports oberts, accés a una web i a la que tinguem unes credencials ens podrem connectar per SSH. També hi ha el port 21 ftp obert i el port 8081 que tée un apache corrent darrere, sembla que tindrem vàris llocs dels quals estirar.

Abans de anar al port 80 per el navegador, farem un wget i un whatweb per veure que hi ha. Ho fem directe a la IP ja que encara no tenim el domini, i així potser el podem treure:
```
┌──(polkali㉿kaliPol)-[~]
└─$ whatweb http://10.10.11.32
http://10.10.11.32 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], RedirectLocation[http://sightless.htb/], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://sightless.htb/ - no address for sightless.htb

```

I obtenim un resultat molt similar, veiem el mateix 302 que teniem amb el whatweb i a Location veiem a on ens ha redirigit, per el port 80.

```
┌──(polkali㉿kaliPol)-[~]
└─$ wget http://10.10.11.32
--2024-09-22 19:56:56--  http://10.10.11.32/
Connecting to 10.10.11.32:80... connected.
HTTP request sent, awaiting response... 302 Moved Temporarily
Location: http://sightless.htb/ [following]
--2024-09-22 19:56:57--  http://sightless.htb/
Resolving sightless.htb (sightless.htb)... failed: Name or service not known.
wget: unable to resolve host address ‘sightless.htb’`
```


Efectivament veiem com ens intenta redirigir al domini redirigeix al domini http://sightless.htb/ . Ara, per tant, hem de posar el nom del domini al nostre fitxer /etc/hosts:

Si anem a veure el que es serveix al port 8081 ens trobem amb una pàgina de login i el que sembla un software anomenat Froxlor, que haurem d'investigar si té alguna vulnerabilitat o potser s'hi pot fer injecció o atacar amb XSS:

![[Pasted image 20240922201616.png]]

En canvi, si anem al port 80 ens trobem que l'Apache segueix la següent pàgina:

![[Pasted image 20240922201643.png]]

Ara mirarem el codi font (Cntrl+U) per veure si podem veure amb què o com està fet per si trobéssim un 'fet amb Wordpress' o alguna cosa per l’estil, abaix de tot de la pàgina web segurament també ho veuríem si fos el cas. He mirat les dues pàgines, tant el formulari ed login com la web de slightless però no he vist res destacable al codi font.

Passarem a analitzar i remenar les web des del navegador. Si anem a Services i cliquem aquí, veiem que hi ha un subdomini que no coneixíem ja que no hem fet cap escaneig de subdominis, l'afegirem a l' /etc/hosts per poder veure què hi ha:

![[Pasted image 20240922211644.png]]
Gràcies a això accedim a un panell que s'anomena SQLPad, que, com anunciava la web de sightless, és una aplicació web que permet a usuaris connectar-se a a vàris servidors SQL a través del navegador:

![[Pasted image 20240922211806.png]]

Sembla que pot ser interessant i podrem treure suc d'aquí. He fet alguns intents d'injecció SQL però no hi ha hagut sort, provaré amb XSS o a veure si interceptan les peticions amb Burpsuite aconseguim alguna cosa més.

Remenant amb Burpsuite veiem com al accedir a l'SQLPad podem veure la versió d'aquest software:

```
`HTTP/1.1 200 OK

Server: nginx/1.18.0 (Ubuntu)

Date: Sun, 22 Sep 2024 20:11:55 GMT

Content-Type: application/json; charset=utf-8

Content-Length: 473

Connection: close

X-DNS-Prefetch-Control: off

Strict-Transport-Security: max-age=15552000; includeSubDomains

X-Download-Options: noopen

X-Content-Type-Options: nosniff

X-XSS-Protection: 0

Referrer-Policy: same-origin

ETag: W/"1d9-E+82Qgtj4TJN18ynAdqcoit4wXQ"



{"currentUser":{"id":"noauth","email":"noauth@example.com","role":"admin","name":"noauth"},"config":{"allowCsvDownload":true,"baseUrl":"","defaultConnectionId":"","editorWordWrap":false,"googleAuthConfigured":false,"localAuthConfigured":true,"publicUrl":"","samlConfigured":false,"samlLinkHtml":"Sign in with SSO","ldapConfigured":false,"ldapRolesConfigured":false,"oidcConfigured":false,"oidcLinkHtml":"Sign in with OpenID","showServiceTokensUI":false},"version":"6.10.0"}`
```

![[Pasted image 20240922221355.png]]

Per tant, ara que tenim la versió de l'SQLPad busquem si hi ha algun POC o exploit per aquesta versió en concret.
