
El primer que farem serà un nmap a la màquina que estem atacant:
``nnmap -sC -sV -v 10.10.11.23``

Un cop fet l'nmap, veiem que la màquina víctima té els següents ports oberts amb els següents serveis:

``

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```


Ara hem de desar la pàgina amb el nom de domini permx.htb al nostre fitxer /etc/hosts per poder accedir-hi, com fem sempre:

``sudo nano /etc/hosts``

``10.10.11.23     permx.htb``

Un cop ho hem fet, accedim a la pàgina web a través del navegador i veiem el següent:

![[Pasted image 20240802204530.png]]

Mirarem de trobar dominis o subdominis a veure si trobem alguna cosa útil de la qual podem estirar. Primer provem a veure si trobem algun domini que ens sigui útil:

```
──(polkali㉿kaliPol)-[~]
└─$ gobuster dir --url http://permx.htb / --wordlist /usr/share/wordlists/dirbuster/directory-list-1.0.txt `
```

Hem trobat algun domini al qual tenim accés, però no hi ha res que ens pugui servir per obtenir accés, per exemple hi ha un domini amb imatges: http://permx.htb/img/

![[Pasted image 20240802213636.png]]

També hem trobat el domini http://permx.htb/js/main.js on hi ha el codi principal de la pàgina web, però al passar-li al ChatGPT sembla que no té cap vulnerabilitat clara a simple vista. El codi:

```
(function ($) {
    "use strict";

    // Spinner
    var spinner = function () {
        setTimeout(function () {
            if ($('#spinner').length > 0) {
                $('#spinner').removeClass('show');
            }
        }, 1);
    };
    spinner();
    
    
    // Initiate the wowjs
    new WOW().init();


    // Sticky Navbar
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.sticky-top').css('top', '0px');
        } else {
            $('.sticky-top').css('top', '-100px');
        }
    });
    
    
    // Dropdown on mouse hover
    const $dropdown = $(".dropdown");
    const $dropdownToggle = $(".dropdown-toggle");
    const $dropdownMenu = $(".dropdown-menu");
    const showClass = "show";
    
    $(window).on("load resize", function() {
        if (this.matchMedia("(min-width: 992px)").matches) {
            $dropdown.hover(
            function() {
                const $this = $(this);
                $this.addClass(showClass);
                $this.find($dropdownToggle).attr("aria-expanded", "true");
                $this.find($dropdownMenu).addClass(showClass);
            },
            function() {
                const $this = $(this);
                $this.removeClass(showClass);
                $this.find($dropdownToggle).attr("aria-expanded", "false");
                $this.find($dropdownMenu).removeClass(showClass);
            }
            );
        } else {
            $dropdown.off("mouseenter mouseleave");
        }
    });
    
    
    // Back to top button
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.back-to-top').fadeIn('slow');
        } else {
            $('.back-to-top').fadeOut('slow');
        }
    });
    $('.back-to-top').click(function () {
        $('html, body').animate({scrollTop: 0}, 1500, 'easeInOutExpo');
        return false;
    });


    // Header carousel
    $(".header-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1500,
        items: 1,
        dots: false,
        loop: true,
        nav : true,
        navText : [
            '<i class="bi bi-chevron-left"></i>',
            '<i class="bi bi-chevron-right"></i>'
        ]
    });


    // Testimonials carousel
    $(".testimonial-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1000,
        center: true,
        margin: 24,
        dots: true,
        loop: true,
        nav : false,
        responsive: {
            0:{
                items:1
            },
            768:{
                items:2
            },
            992:{
                items:3
            }
        }
    });
    
})(jQuery);
```

Com que no hem tingut els millors resultats cercant dominis, passarem a fer una cerca per subdominis a veure si hi ha més sort:

```
ffuf -u http://board.htb -H "Host: FUZZ.permx.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -c -fs 15949`
```

- **`-c`**:
    
    - `-c` activa la sortida de colors, fent que sigui més fàcil llegir i interpretar la sortida a la terminal.
- **`-fs 15949`**:
    
    - `-fs` significa "filter size" (filtrar per mida). Això indica que s'ha de filtrar les respostes amb una mida específica.
    - En aquest cas, `ffuf` ignorarà totes les respostes que tinguin una mida de 15949 bytes.
**`-H "Host: FUZZ.permx.htb"`**:

- `-H` permet definir una capçalera HTTP personalitzada. En aquest cas, s'està definint la capçalera `Host`.
- `FUZZ` és una paraula clau especial en `ffuf` que serà substituïda per cada entrada de la llista de paraules.
- Això vol dir que `ffuf` provarà diferents subdominis substituint `FUZZ` per cada subdomini de la llista en la capçalera `Host`.

No hi ha hagut èxit tampoc. Tornaré a escanejar els dominis i subdominis amb llistes i comandes diferents. La llista que hem utilitzat és la medium, a veure si així tenim més sort. Primer provem de trobar dominis amb aquesta llista:

``gobuster dir --url http://permx.htb / --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt``

Seguim sense tenir èxit, tornarem a provar de fer una cerca per subdominis agafant una llista molt gran, que té el milió top de subdominis, a veure si trobem alguna cosa:

```
ffuf -u http://permx.htb -H "Host: FUZZ.permx.htb" -w /usr/share/wordlists/amass/subdomains-top1million-110000.txt -mc 200,403 -c

```

Hem utilitzat ffuf filtrant només per els status 200 i 403 (forbidden). Ara hi ha hagut èxit i hem trobat dos subdomins:

```
┌──(polkali㉿kaliPol)-[~]
└─$ ffuf -u http://permx.htb -H "Host: FUZZ.permx.htb" -w /usr/share/wordlists/amass/subdomains-top1million-110000.txt -mc 200,403 -c


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/amass/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,403
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 60ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 87ms]
:: Progress: [114441/114441] :: Job [1/1] :: 716 req/sec :: Duration: [0:02:54] :: Errors: 0 ::`
```

Provarem amb el subdomini lms ja que www ha de ser l'àlies que tenen posat al fitxer .conf de l'Apache de la pàgina. Per tant, desarem al fitxer /etc/hosts els subdomini:

``10.10.11.23     permx.htb lms.permx.htb``

I a la pàgina ens trobem el següent:

![[Pasted image 20240802224129.png]]

A sota a la dreta veiem el nom de l'administrador de la pàgina:

![[Pasted image 20240802224156.png]]

Si cliquem al nom de l'administrador veiem que se'ns obre una finestra per poder enivar-li un correu:

![[Pasted image 20240802224233.png]]

Provem credencials per defecte que s'acostumen a utilitzar al login (admin:admin, root:root, etc) però no tenim èxit, hem provat també injecció sql força bàsica i tampoc hi ha hagut èxit:

![[Pasted image 20240802224505.png]]

Per tant, ens centrarem en el següent que es veu de forma clara a la pàgina, que és Chamilo que cercant per internet veiem que és un sistema d'aprenentatge electrònic i de gestió de continguts de programari lliure, orientat a millorar l'accés a l'educació i el coneixement a nivell mundial. Per tant bucarem si té algun POC o exploit per el qual podem iniciar sessió en aquest login.

