Primer de tot fem un nmap per veure els ports que hi ha oberts a la màquina que estem atacant:

```
`┌──(root㉿kali)-[/home/polkali]
└─# nmap -v -sC -sV 10.10.11.8 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-24 18:42 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
Initiating NSE at 18:42
Completed NSE at 18:42, 0.00s elapsed
Initiating Ping Scan at 18:42
Scanning 10.10.11.8 [4 ports]
Completed Ping Scan at 18:42, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:42
Completed Parallel DNS resolution of 1 host. at 18:42, 0.00s elapsed
Initiating SYN Stealth Scan at 18:42
Scanning 10.10.11.8 [1000 ports]
Discovered open port 22/tcp on 10.10.11.8
Discovered open port 5000/tcp on 10.10.11.8
Completed SYN Stealth Scan at 18:42, 3.76s elapsed (1000 total ports)
Initiating Service scan at 18:42
Scanning 2 services on 10.10.11.8
Completed Service scan at 18:44, 97.86s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.8.
Initiating NSE at 18:44
Completed NSE at 18:44, 2.95s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 1.10s elapsed
Initiating NSE at 18:44
Completed NSE at 18:44, 0.00s elapsed
Nmap scan report for 10.10.11.8
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Sun, 24 Mar 2024 17:42:42 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>`
```
|_    </html>

Ens trobem amb el port 22 obert per SSH i el port 5000 hi ha Werkzeug que és una completa biblioteca d'aplicacions web WSGI. Va començar com una simple col·lecció de diverses utilitats per a aplicacions WSGI i s'ha convertit en una de les biblioteques d'utilitats WSGI més avançades.

Ara provarem d'accedir a la pàgina pel port 5000 i ens trobem això:

![[Pasted image 20240324184758.png]]

Ara passo una eina com dirsearch per veure quins directoris hi ha ocults als quals hi puc accedir. Afegiré al fitxer de /etc/hosts el nom de domini associat a la IP per poder utilitzar-lo també a la hora d'utilitzar eines:

``10.10.11.8      headless.htb``

```
`┌──(root㉿kali)-[/home/polkali]
└─# dirsearch -u http://10.10.11.8:5000/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict
/usr/local/lib/python3.11/dist-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.6) or chardet (5.2.0)/charset_normalizer (2.0.3) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "

  _|. _ _  _  _  _ _|_    v0.4.3                                                                             
 (_||| _) (/_(_|| (_| )                                                                                      
                                                                                                             
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/polkali/reports/http_10.10.11.8_5000/__24-03-24_18-52-25.txt

Target: http://10.10.11.8:5000/

[18:52:25] Starting:                                                                                         
[18:53:22] 401 -  317B  - /dashboard                                        
[18:54:34] 200 -    2KB - /support                                          
                                                                             
Task Completed                                                                                               
                            `
``` 


Trobem tant el directori /dashboard com el /support. Al directori /dashboard no hi tenim autoritzat l'accés, però si que tenim accés al directori /support, on hi ha un formulari que a primera vista sembla que podria ser molt útil.

Primer provarem amb injecció sql a veure si obtenim algun resultat:

![[Pasted image 20240324192506.png]]

Sembla que potser podrem obtenir alguna cosa, ara provarem amb SQLmap:

```
`[19:29:33] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[19:29:34] [WARNING] POST parameter 'message' does not seem to be injectable
[19:29:34] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 19:29:34 /2024-03-24/`
```

Provarem Cross-Site Scripting (XSS), per exemple provarem el següent a tots els camps del formulari on ens el deixi posar (tot i que només posant-lo a 1 segurament també funcioni). És un exemple d'una etiqueta HTML que executa una funció JavaScript. En aquest cas, la funció JavaScript simplement mostraria una finestra emergent amb el text "hacked" :

``<script>alert("hacked")</script>``

![[Pasted image 20240406222638.png]]

Al fer-ho l'atac XSS ens retorna el següent missatge:

![[Pasted image 20240406222621.png]]

El missatge ens diu que la nostre IP s'ha marcat i s'ha enviat un informe als administradors del lloc web perquè investiguin el cas.



