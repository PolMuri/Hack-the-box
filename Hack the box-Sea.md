Actualment està en progrés


El primer que farem serà un nmap a la màquina que estem atacant:
``nmap -sC -sV -v 10.10.11.28``

Un cop fet l'nmap, veiem que la màquina víctima té els següents ports oberts amb els següents serveis:
``

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e3:54:e0:72:20:3c:01:42:93:d1:66:9d:90:0c:ab:e8 (RSA)
|   256 f3:24:4b:08:aa:51:9d:56:15:3d:67:56:74:7c:20:38 (ECDSA)
|_  256 30:b1:05:c6:41:50:ff:22:a3:7f:41:06:0e:67:fd:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Sea - Home
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


Ara hem de desar la pàgina amb el nom de domini permx.htb al nostre fitxer /etc/hosts per poder accedir-hi, com fem sempre:

``sudo nano /etc/hosts``

``10.10.11.28     sea.htb``

Un cop ho hem fet, accedim a la pàgina web a través del navegador i veiem el següent:

![[Pasted image 20240811150345.png]]

Veiem que és una pàgina d'una empresa que es dedica a organitzar aventures per ciclistes de nit i que ofereixen premis per els 3 primers ciclistes.

A la pàgina web no hi veig res a primer cop d'ull, per tant mirare el codi font:

```
<!DOCTYPE html>
<html lang="en">
    <head>
    	<meta charset="UTF-8">
    	<meta http-equiv="X-UA-Compatible" content="IE=edge">
    	<meta name="viewport" content="width=device-width, initial-scale=1">
    	
        <title>Sea - How to</title>
        <meta name="description" content="A page description is also good for search engines.">
        <meta name="keywords" content="Enter, keywords, for, this page">
    	
        <link rel="stylesheet" href="[https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css](view-source:https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css)" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

	<!-- Admin CSS -->
	
	<!-- Theme CSS -->
	<link rel="stylesheet" href="[http://sea.htb/themes/bike/css/style.css](view-source:http://sea.htb/themes/bike/css/style.css)">
    </head>

    <body>
    	<div class="hero">
    		<div class="parallax-layer layer-6"></div>
    		<div class="parallax-layer layer-5"></div>
    		<div class="parallax-layer layer-4"></div>
    		<div class="parallax-layer bike-1"></div>
    		<div class="parallax-layer bike-2"></div>
    		<div class="parallax-layer layer-3"></div>
    		<div class="parallax-layer layer-2"></div>
    		<div class="parallax-layer layer-1"></div>
    		<div class="logo">
    			<center><img src="[http://sea.htb/themes/bike/img/velik71-new-logotip.png](view-source:http://sea.htb/themes/bike/img/velik71-new-logotip.png)" alt="" /></center>
    		</div>
    	</div>
    
                    
    	<nav class="navbar navbar-default">
    		<div class="container">
    			<div class="col-sm-5 text-center">
    				<div class="navbar-header">
    					<button type="button" class="navbar-toggle" data-toggle="collapse" data-target="#navMobile">&#9776;</button>
    					<a href="[http://sea.htb/](view-source:http://sea.htb/)"><h1>Sea</h1></a>
    				</div>
    			</div>
    			<div class="col-sm-7 text-center">
    				<div class="collapse navbar-collapse" id="navMobile">
    					<ul class="nav navbar-nav navbar-right">
                            <li class="nav-item ">
						<a class="nav-link" href="[http://sea.htb/home](view-source:http://sea.htb/home)">Home</a></li><li class="nav-item active ">
						<a class="nav-link" href="[http://sea.htb/how-to-participate](view-source:http://sea.htb/how-to-participate)">How to participate</a></li>
    					</ul>
    				</div>
    			</div>
    		</div>
    	</nav>
    
    	<div class="container">
    		<div class="col-xs-12 col-sm-8">
    			<div class="whiteBackground grayFont padding20 rounded5">
                    <h1>How can I participate?</h1>
<p>To participate, you only need to send your data as a participant through <a href="[http://sea.htb/contact.php](view-source:http://sea.htb/contact.php)">contact</a>. Simply enter your name, email, age and country. In addition, you can optionally add your website related to your passion for night racing.</p>
    			</div>
    		</div>
    		<div class="col-xs-12 col-sm-4">
    			<div class="visible-xs spacer20"></div>
    			<div class="blueBackground padding20 rounded5">
                    <h2>About</h2>

<br>
<p>We are a company dedicated to organizing races on an international level. Our main focus is to ensure that our competitors enjoy an exciting night out on the bike while participating in our events.</p>
    			</div>
    		</div>
    	</div>
        <br><br><br><br>
    	<footer class="container-fluid">
    		<div class="padding20 text-right">
                ©2024 Sea
    		</div>
    	</footer>
    
        <script src="[https://code.jquery.com/jquery-1.12.4.min.js](view-source:https://code.jquery.com/jquery-1.12.4.min.js)" integrity="sha384-nvAa0+6Qg9clwYCGGPpDQLVpLNn0fRaROjHqs13t4Ggj3Ez50XnGQqc/r8MhnRDZ" crossorigin="anonymous"></script>
        <script src="[https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js](view-source:https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js)" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
        
    </body>
</html>`
```

Aquí al codi font hi trobem un formulari web, a través del qual s'hi han d'enviar les nostres dades per poder participar als esdeveniments:

![[Pasted image 20240811151709.png]]

El codi font del formulari:
```
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Contact Form</title>
<style>
    body, html {
        margin: 0;
        padding: 0;
        height: 100%;
        overflow: hidden;
    }
    #background {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: #00274c;
        z-index: -1;
    }
    #stars {
        width: 1px;
        height: 1px;
        background: #fff;
        position: absolute;
        animation: twinkle 2s infinite;
    }
    @keyframes twinkle {
        0% {
            opacity: 1;
        }
        100% {
            opacity: 0;
        }
    }
    #container {
        position: relative;
        z-index: 1;
        max-width: 600px;
        margin: 50px auto;
        padding: 20px;
        background-color: rgba(255, 255, 255, 0.9);
        border-radius: 10px;
        box-shadow: 0 0 20px rgba(0, 0, 0, 0.2);
    }
    h1 {
        text-align: center;
        margin-bottom: 30px;
        color: #00274c;
    }
    label {
        display: block;
        margin-bottom: 5px;
        color: #00274c;
    }
    input[type="text"],
    input[type="email"],
    input[type="number"] {
        width: calc(100% - 12px);
        padding: 8px;
        margin-bottom: 20px;
        border: 1px solid #ccc;
        border-radius: 5px;
    }
    input[type="text"]:focus,
    input[type="email"]:focus,
    input[type="number"]:focus {
        outline: none;
        border-color: #6fb3e0;
    }
    input[type="submit"] {
        background-color: #6fb3e0;
        color: #fff;
        border: none;
        padding: 10px 20px;
        border-radius: 5px;
        cursor: pointer;
    }
    input[type="submit"]:hover {
        background-color: #4a90c6;
    }
</style>
</head>
<body>

 

    <div id="background">
        <div id="stars"></div>
    </div>
    <div id="container">
        <h1>Competition registration - Sea</h1>
        
        <form action="[/contact.php](view-source:http://sea.htb/contact.php)" method="post">
            <label for="name">Name:</label>
            <input type="text" id="name" name="name" required>

            <label for="email">Email:</label>
            <input type="email" id="email" name="email" required>

            <label for="age">Age:</label>
            <input type="number" id="age" name="age" required>

            <label for="country">Country:</label>
            <input type="text" id="country" name="country" required>

            <label for="website">Website:</label>
            <input type="text" id="website" name="website">

            <input type="submit" value="Submit">
        </form>
    </div>
</body>
</html>

```

Té vàris camps com a required, i el de website no, per tant provarem de fer injecció sql a veure si obtenim algun resultat. He encès el Burpsuite per veure com va la petició, quina info tinc i què rebo. Al fer la petició i fer un POST enviant el formulari veig el següent:

![[Pasted image 20240811154042.png]]


```
POST /contact.php HTTP/1.1

Host: sea.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Content-Type: application/x-www-form-urlencoded

Content-Length: 116

Origin: http://sea.htb

Connection: close

Referer: http://sea.htb/contact.php

Cookie: PHPSESSID=1a0ifv2he709ov0itfm01pqj7t

Upgrade-Insecure-Requests: 1



name=%27+OR+%271%27%3D%271&email=hello%40hello.com&age=2&country=%27+OR+%271%27%3D%271&website=%27+OR+%271%27%3D%271`
```

I veiem el missatge per pantalla de que s'ha enviat el formulari correctament:

![[Pasted image 20240811153911.png]]

Ara per veure si el servidor és vulnerable a XSS modificarem els camps de text (com `name`, `country`, o `website`) per introduir codi JavaScript.

- En el camp `name`, provarem a introduir: `<script>alert('XSS')</script>`
- En el camp `website`, provarem amb: `http://evil.com"><script>alert('XSS')</script>`

No hem tingut èxit. He provat una enumeració de dominis i subdominis però tampoc he tingut èxit:

``ffuf -u http://sea.htb -H "Host: FUZZ.sea.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -c -fs 15949``

Últimament la gran majoria de màquines que hem fet, tenien algun domini ocult el qual havíem de descobrir, provarem amb una altra cerca de subdominis, ho provarem amb la llista de directoris medium, així estem en un terme mig i no haurem d'esperar molt com si féssim la big i tindrem més profunditat i possibles resultats que si ho fessim amb la small. Trobem directoris com themes, messages, plugins o data que ens redirigeixen, ja que tenen un 301, i ens redirigeixen i ens diuen que no tenim accés:

``ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://sea.htb/FUZZ``

```
themes                  [Status: 301, Size: 230, Words: 14, Lines: 8, Duration: 95ms]
0                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 97ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 933ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 938ms]
data                    [Status: 301, Size: 228, Words: 14, Lines: 8, Duration: 55ms]
# on atleast 2 different hosts [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 1374ms]
# Copyright 2007 James Fisher [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 1387ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 1450ms]
#                       [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 1450ms]
plugins                 [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 55ms]
messages                [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 96ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 474ms]
````

![[Pasted image 20240817174755.png]]

Com a curiositat i lligat a la temàtica de la pàgina web, hi ha el domini bike:

![[Pasted image 20240817175422.png]]

Provaré a veure si a través d'aquí aconsegueixo alguna cosa amb útil. Provaré a veure si puc trobar cercant per els dominis que he trobat algun domini, és a dir dominis dins el domini. Ara però, filtrarem per respostes 200 i 301. Anirem fent això amb els diferents dominis dins de dominis trobats fins que trobem alguna cosa útil:

``ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://sea.htb/themes/bike/FUZZ -mc 200,301``

Hem obtingut aquestes respostes:

```
img                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 61ms]
home                    [Status: 200, Size: 3650, Words: 582, Lines: 87, Duration: 62ms]
version                 [Status: 200, Size: 6, Words: 1, Lines: 2, Duration: 68ms]
css                     [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 68ms]
summary                 [Status: 200, Size: 66, Words: 9, Lines: 2, Duration: 60ms]
404                     [Status: 200, Size: 3341, Words: 530, Lines: 85, Duration: 68ms]
LICENSE                 [Status: 200, Size: 1067, Words: 152, Lines: 22, Duration: 68ms`
```

Hem trobat alguns directoris dins el directori /themes/bike, penso que per aquí al ser una web sobre competicions de bicis hem d'anar bé ja que portem molta estona i encara no hem trobat res. Enviaré la petició al repeater del Burpsuite així podré manipular-la des d'allà i veure la resposta.
