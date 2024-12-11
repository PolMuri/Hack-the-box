Anirem directament al reconeixement actiu, fent un nmap directament i saltant-nos el reconeixement passiu:
```
──(kali㉿kali)-[~]
└─$ nmap -sC -sV -v 10.10.11.47
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-08 09:52 CET
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating Ping Scan at 09:52
Scanning 10.10.11.47 [4 ports]
Completed Ping Scan at 09:52, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:52
Completed Parallel DNS resolution of 1 host. at 09:52, 0.04s elapsed
Initiating SYN Stealth Scan at 09:52
Scanning 10.10.11.47 [1000 ports]
Discovered open port 80/tcp on 10.10.11.47
Discovered open port 22/tcp on 10.10.11.47
Completed SYN Stealth Scan at 09:52, 1.06s elapsed (1000 total ports)
Initiating Service scan at 09:52
Scanning 2 services on 10.10.11.47
Completed Service scan at 09:52, 6.19s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.47.
Initiating NSE at 09:52
Completed NSE at 09:52, 2.43s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.41s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Nmap scan report for 10.10.11.47
Host is up (0.041s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
|_http-server-header: Apache
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Initiating NSE at 09:52
Completed NSE at 09:52, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.02 seconds
           Raw packets sent: 1004 (44.152KB) | Rcvd: 1001 (40.048KB)

```

Trobem dos ports oberts, accés a una web pel port 80 i a la que tinguem unes credencials ens podrem connectar per SSH ja que també hi ha accés al port 22 que és el port ssh per defecte. Ara, per tant, afegirem al fitxer /etc/hosts aquesta IP i l'associarem al nom de domini linkvortex.htb.

Abans de anar al port 80 per el navegador però, farem un wget/curl i un whatweb per veure que hi ha.

```
┌──(kali㉿kali)-[~]
└─$ whatweb http://linkvortex.htb                                                                   
http://linkvortex.htb [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.10.11.47], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], Title[BitByBit Hardware], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

Amb aquest whatweb veiem informació que ens pot ser rellevant:


El framework Ghost que és un sistema de gestió de continguts (CMS). En aquest cas, la versió és la 5.58. Cal buscar si hi ha vulnerabilitats conegudes per aquesta versió. He vist per internet que Ghost sovint funciona amb node.js i el framework Express pel que veiem, o sigui que potser a algun lloc veiem la versió i és vulnerable.

JQuery 3.5.1 es pot investigar si és vulnerable a problemes com Cross-Site Scripting (XSS). També hi ha Open-Graph i compatibilitat amb IE, tocarà investigar-ho.

Ara fem un curl:
```

┌──(kali㉿kali)-[~]
└─$ curl http://linkvortex.htb
<!DOCTYPE html>
<html lang="en">
<head>

    <title>BitByBit Hardware</title>
    <meta charset="utf-8" />
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <meta name="HandheldFriendly" content="True" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    
    <link rel="preload" as="style" href="/assets/built/screen.css?v=73b5f46ae9" />
    <link rel="preload" as="script" href="/assets/built/casper.js?v=73b5f46ae9" />

    <link rel="stylesheet" type="text/css" href="/assets/built/screen.css?v=73b5f46ae9" />

    <meta name="description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <link rel="canonical" href="http://linkvortex.htb/">
    <meta name="referrer" content="no-referrer-when-downgrade">
    
    <meta property="og:site_name" content="BitByBit Hardware">
    <meta property="og:type" content="website">
    <meta property="og:title" content="BitByBit Hardware">
    <meta property="og:description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <meta property="og:url" content="http://linkvortex.htb/">
    <meta property="article:publisher" content="https://www.facebook.com/ghost">
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="BitByBit Hardware">
    <meta name="twitter:description" content="Your trusted source for detailed, easy-to-understand computer parts info">
    <meta name="twitter:url" content="http://linkvortex.htb/">
    <meta name="twitter:site" content="@ghost">
    
    <script type="application/ld+json">
{
    "@context": "https://schema.org",
    "@type": "WebSite",
    "publisher": {
        "@type": "Organization",
        "name": "BitByBit Hardware",
        "url": "http://linkvortex.htb/",
        "logo": {
            "@type": "ImageObject",
            "url": "http://linkvortex.htb/favicon.ico"
        }
    },
    "url": "http://linkvortex.htb/",
    "mainEntityOfPage": "http://linkvortex.htb/",
    "description": "Your trusted source for detailed, easy-to-understand computer parts info"
}
    </script>

    <meta name="generator" content="Ghost 5.58">
    <link rel="alternate" type="application/rss+xml" title="BitByBit Hardware" href="http://linkvortex.htb/rss/">
    
    <script defer src="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/sodo-search.min.js" data-key="054f7096476b0e8c7ec591c72c" data-styles="https://cdn.jsdelivr.net/ghost/sodo-search@~1.1/umd/main.css" data-sodo-search="http://linkvortex.htb/" crossorigin="anonymous"></script>
    
    <link href="http://linkvortex.htb/webmentions/receive/" rel="webmention">
    <script defer src="/public/cards.min.js?v=73b5f46ae9"></script><style>:root {--ghost-accent-color: #1c1719;}</style>
    <link rel="stylesheet" type="text/css" href="/public/cards.min.css?v=73b5f46ae9">

</head>
<body class="home-template is-head-left-logo has-cover">
<div class="viewport">

    <header id="gh-head" class="gh-head outer">
        <div class="gh-head-inner inner">
            <div class="gh-head-brand">
                <a class="gh-head-logo no-image" href="http://linkvortex.htb">
                        BitByBit Hardware
                </a>
                <button class="gh-search gh-icon-btn" aria-label="Search this site" data-ghost-search><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" width="20" height="20"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></button>
                <button class="gh-burger"></button>
            </div>

            <nav class="gh-head-menu">
                <ul class="nav">
    <li class="nav-home nav-current"><a href="http://linkvortex.htb/">Home</a></li>
    <li class="nav-about"><a href="http://linkvortex.htb/about/">About</a></li>
</ul>

            </nav>

            <div class="gh-head-actions">
                        <button class="gh-search gh-icon-btn" data-ghost-search><svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" width="20" height="20"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></button>
            </div>
        </div>
    </header>

    <div class="site-content">
        
<div class="site-header-content outer">


        <div class="site-header-inner inner">
                    <h1 class="site-title">BitByBit Hardware</h1>
                <p class="site-description">Your trusted source for detailed, easy-to-understand computer parts info</p>
        </div>

</div>

<main id="site-main" class="site-main outer">
<div class="inner posts">

    <div class="post-feed">
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/psu/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The Power Supply
                </h2>
            </header>
                <div class="post-card-excerpt">A power supply unit (PSU) converts the alternating current (AC) from your wall outlet into direct current (DC) that the computer components require. It supplies power to the motherboard, CPU, GPU, storage drives, fans, and other peripherals. Without a functioning PSU, a computer cannot operate.

Functions of a Power Supply</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2024-08-05">Aug 5, 2024</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/storage-drive/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The CMOS
                </h2>
            </header>
                <div class="post-card-excerpt">CMOS is a type of semiconductor technology used to store small amounts of data on the motherboard. This data includes system settings and configuration information required for the computer to boot correctly. In modern systems, CMOS technology is primarily used in the CMOS RAM chip, which is powered by a</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2024-05-07">May 7, 2024</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/vga/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The Video Graphics Array
                </h2>
            </header>
                <div class="post-card-excerpt">The term VGA can refer to either the Video Graphics Array specification or the physical VGA connector often used for computer video output. Below, I'll provide a comprehensive overview of both aspects to give you a full understanding of VGA in the context of computer hardware and display technology.


Video</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2024-04-16">Apr 16, 2024</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/ram/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The Random Access Memory
                </h2>
            </header>
                <div class="post-card-excerpt">Random Access Memory (RAM) is a crucial component in all computing devices, serving as the main short-term data storage space. RAM stores the data and programs that a CPU needs in real time or near real time. Unlike hard drives or SSDs (Solid State Drives), which store data permanently, RAM</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2024-04-01">Apr 1, 2024</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/cmos/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The Motherboard
                </h2>
            </header>
                <div class="post-card-excerpt">A motherboard is a complex printed circuit board (PCB) that facilitates communication between all critical electronic components of a computer, including the CPU (Central Processing Unit), memory (RAM), storage devices, video cards, and other peripheral devices. It distributes power to these components and allows for communication between the CPU, memory,</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2024-03-11">Mar 11, 2024</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
            
<article class="post-card post no-image keep-ratio">


    <div class="post-card-content">

        <a class="post-card-content-link" href="/cpu/">
            <header class="post-card-header">
                <div class="post-card-tags">
                </div>
                <h2 class="post-card-title">
                    The Central Processing Unit
                </h2>
            </header>
                <div class="post-card-excerpt">The Central Processing Unit (CPU), often simply referred to as the processor, is the primary component of a computer that performs most of the processing inside a computer. To understand its significance, it's important to dive into its architecture, functions, and how it integrates within the broader context of computer</div>
        </a>

        <footer class="post-card-meta">
            <time class="post-card-meta-date" datetime="2023-12-11">Dec 11, 2023</time>
                <span class="post-card-meta-length">2 min read</span>
        </footer>

    </div>

</article>
    </div>

    <nav class="pagination">
    <span class="page-number">Page 1 of 1</span>
</nav>


</div>
</main>

    </div>

    <footer class="site-footer outer">
        <div class="inner">
            <section class="copyright"><a href="http://linkvortex.htb">BitByBit Hardware</a> &copy; 2024</section>
            <nav class="site-footer-nav">
                <ul class="nav">
    <li class="nav-sign-up nav-current"><a href="#/portal/">Sign up</a></li>
</ul>

            </nav>
            <div class="gh-powered-by"><a href="https://ghost.org/" target="_blank" rel="noopener">Powered by Ghost</a></div>
        </div>
    </footer>

</div>


<script
    src="https://code.jquery.com/jquery-3.5.1.min.js"
    integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0="
    crossorigin="anonymous">
</script>
<script src="/assets/built/casper.js?v=73b5f46ae9"></script>
<script>
$(document).ready(function () {
    // Mobile Menu Trigger
    $('.gh-burger').click(function () {
        $('body').toggleClass('gh-head-open');
    });
    // FitVids - Makes video embeds responsive
    $(".gh-content").fitVids();
});
</script>



</body>
</html>
                                         
```

Amb aquest curl hi ha llibreries externes de jquery carregades sense una verificació estricta, i s'haurà de mirar el codi personalitzat que es carrega a veure si s'hi pot fer XSS. El més rellevant potser és que hi ha un software que s'anomena Ghost, i veiem la versió que té, si trobem exploits per ell els podríem utilitzar: `<meta name="generator" content="Ghost 5.58">`. També hi ha recursos que no es carreguen per https i es carreguen per http. Haurem de veure si alguna d'aquestes coses ens és útil.

Ara anirem a la pàgina web a veure què veiem:

![image](https://github.com/user-attachments/assets/0dee336b-0c0d-457e-aa33-fc11563a8099)


A sota de tot veiem powered by ghost, el software que hem comentat abans al fer el curl, i hi ha un formulari de login:

![image](https://github.com/user-attachments/assets/77e9b4bc-aabe-423a-a63a-e59744cff4a7)


Al clicar el formulari de Sign up no carrega res, però si que veiem que la url canvia:

![image](https://github.com/user-attachments/assets/d92b40bb-8cfc-4903-9fcd-337e692fd641)


Per tant, ara faré un escaneig de subdominis i dominis a veure si aconseguim alguna cosa més. Amb l'escaneig de subdominis fet amb fuff i amb el fitxer de subdominis més gros que tinc a la màquina kali i hem trobat un subdomini -> dev.linkvortex.htb:

```
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/amass/subdomains-top1mil-110000.txt -u http://linkvortex.htb -H "Host:FUZZ.linkvortex.htb" -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/amass/subdomains-top1mil-110000.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 322ms]
:: Progress: [114606/114606] :: Job [1/1] :: 332 req/sec :: Duration: [0:14:25] :: Errors: 0 ::
```

Abans d'accedir-hi però, farem l'escaneig de dominis a veure si trobem alguna cosa més, en aquesta ocasió ho he fet amb fuff, però no he trobat res rellevant, he filtrat per els que retornen un codi 200 de resposta del servidor, ja que de 301 n'hi havia masses i era impossible filtrar. Per tant, ara anirem al subdomini que hem trobat: dev.linkvortex.htb. Al subdomini si hi anem a través del navegador ens trobem amb que hi ha un avís que la pàgina està en construcció i que en breus la llençaran i estarà en funcionament:

![image](https://github.com/user-attachments/assets/c2e87ecd-4ab2-410e-a9eb-557b88276f02)

Ara, cercarem a aquest subdomini directoris o fitxers que ens puguin ser útils amb dirb, per canviar una mica d'eina:

```                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]
└─$ dirb http://dev.linkvortex.htb /usr/share/wordlists/dirb/common.txt


-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Dec  9 13:42:22 2024
URL_BASE: http://dev.linkvortex.htb/
WORDLIST_FILES: /usr/share/wordlists/dirb/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://dev.linkvortex.htb/ ----
+ http://dev.linkvortex.htb/.git/HEAD (CODE:200|SIZE:41)                                                                                                                                                                                  
+ http://dev.linkvortex.htb/cgi-bin/ (CODE:403|SIZE:199)                                                                                                                                                                                  
+ http://dev.linkvortex.htb/index.html (CODE:200|SIZE:2538)                                                                                                                                                                               
+ http://dev.linkvortex.htb/server-status (CODE:403|SIZE:199)                                                                                                                                                                             
                                                                                                                                                                                                                                          
-----------------
END_TIME: Mon Dec  9 13:51:01 2024
DOWNLOADED: 4612 - FOUND: 4
```

Sembla que l'únic interessant trobat és el que sembla ser un repositori de GitHub, anirem a la URL a veure què trobem i també podem descarregarlo a veure què hi ha ja que això indica que el repositori Git és accessible al servidor. Això pot ser una vulnerabilitat seriosa, ja que et permet descarregar el repositori complet i accedir al seu historial, commits, i fitxers sensibles que podrien haver estat eliminats però segueixen estant disponibles al repositori. Efectivament, si anem a la ruta a través de la url veiem el repositori i podem accedir als seus fitxers i directoris:

![image](https://github.com/user-attachments/assets/054034fe-ba1b-42bd-a554-e6db5867aa73)


![image](https://github.com/user-attachments/assets/660a407a-8821-47f0-9240-84a0381d6a62)


El que faré serà descarregar el repositori amb les dades que hi ha al fitxer config:
```
┌──(kali㉿kali)-[~/Documents/LinkVortex]
└─$ git clone https://github.com/TryGhost/Ghost.git
Cloning into 'Ghost'...
remote: Enumerating objects: 405239, done.
remote: Counting objects: 100% (3604/3604), done.
remote: Compressing objects: 100% (1572/1572), done.
remote: Total 405239 (delta 2396), reused 2903 (delta 1992), pack-reused 401635 (from 1)
Receiving objects: 100% (405239/405239), 322.77 MiB | 6.11 MiB/s, done.
Resolving deltas: 100% (273926/273926), done.
                                                                                                                           
┌──(kali㉿kali)-[~/Documents/LinkVortex]
└─$ ls -la
total 12
drwxrwxr-x 3 kali kali 4096 Dec 10 10:57 .
drwxr-xr-x 5 kali kali 4096 Dec 10 10:57 ..
drwxrwxr-x 9 kali kali 4096 Dec 10 10:59 Ghost
```
```
┌──(kali㉿kali)-[~/Documents/LinkVortex]
└─$ cd Ghost     
                                                                                                                           
┌──(kali㉿kali)-[~/Documents/LinkVortex/Ghost]
└─$ ls -la
total 1540
drwxrwxr-x  9 kali kali    4096 Dec 10 10:59 .
drwxrwxr-x  3 kali kali    4096 Dec 10 10:57 ..
drwxrwxr-x  2 kali kali    4096 Dec 10 10:59 .devcontainer
drwxrwxr-x  5 kali kali    4096 Dec 10 10:59 .docker
-rw-rw-r--  1 kali kali      62 Dec 10 10:59 .dockerignore
-rw-rw-r--  1 kali kali     312 Dec 10 10:59 .editorconfig
drwxrwxr-x  8 kali kali    4096 Dec 10 10:59 .git
-rw-rw-r--  1 kali kali     122 Dec 10 10:59 .gitattributes
drwxrwxr-x  7 kali kali    4096 Dec 10 10:59 .github
-rw-rw-r--  1 kali kali    3276 Dec 10 10:59 .gitignore
-rw-rw-r--  1 kali kali     270 Dec 10 10:59 .gitmodules
drwxrwxr-x  2 kali kali    4096 Dec 10 10:59 .vscode
-rw-rw-r--  1 kali kali    1065 Dec 10 10:59 LICENSE
-rw-rw-r--  1 kali kali    2687 Dec 10 10:59 PRIVACY.md
-rw-rw-r--  1 kali kali    5187 Dec 10 10:59 README.md
-rw-rw-r--  1 kali kali     518 Dec 10 10:59 SECURITY.md
drwxrwxr-x 12 kali kali    4096 Dec 10 10:59 apps
-rw-rw-r--  1 kali kali    1794 Dec 10 10:59 compose.yml
drwxrwxr-x 88 kali kali    4096 Dec 10 10:59 ghost
-rw-rw-r--  1 kali kali    1113 Dec 10 10:59 nx.json
-rw-rw-r--  1 kali kali    4369 Dec 10 10:59 package.json
-rw-rw-r--  1 kali kali 1479141 Dec 10 10:59 yarn.lock
```

Ara tocarà revisar la informació del repositori descarregat i a veure què trobem que ens pugui ser d'utilitat.



