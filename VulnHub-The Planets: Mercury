Workshop 5

1. Quins ports té oberts la víctima?

Fent un simple nmap no he trobat tots els ports oberts:

Per tant he fet un nmap més complex per veure’ls i trobar-los tots:




























2. Quin contingut pots trobar a la web?

Trobem una pàgina web que s’està fent:


3. Si intentes accedir a un URL que no existeix al servidor, quin URL en pots extreure del missatge que torna?








I podem treure aquestes 3 url’s:

robots.txt, index, mercuryfacts 

Veiem també que la web està feta amb Django.

4. Accedeix al nou URL i visita el planeta de mercuri. Explorant, quina conclusió en pots treure de l’URL?


















Si fem alguna prova i hi afegim un número a la url de forma aleatòria ens retorna “facts” sobre el planeta (entenc que busca a la BD per ID que és el que passem de número “facts” que hi té guardats):




5. Comprova si al darrere hi ha alguna base de dades. Pots utilitzar la comanda sqlmap amb el paràmetre –dbs.

Pel que sembla la BD que hi ha al darrere és un MySQL:
















6. Un cop tens el nom de la base de dades, llista el contingut amb el paràmetre –dump.

Trobem els noms d’usuaris i contrasenyes de la BD mercury:






7. Amb la informació que tens, ja pots entrar al servidor. Adjunta una captura de pantalla per demostrar que hi has entrat.

Hi entro amb el compte webmaster:



















8. Obté les credencials d’un segon usuari amb més privilegis. Quines són?




















Veig que hi ha root, mercury o també hi podria haver linuxmaster.





Ara obtindrem les credencials de l’usuari linuxmaster ja que hi ha la seva password guardada en format Base64:

I obtenim la seva password:





























I ara ens loguejem amb l’usuari linuxmaster:






Activitat addicional i voluntària: Escalada de privilegis per ser root. 
Executa les comandes per identificar els drets i privilegis de l'usuari actual. 
● find / -type f -perm -u=s 

○ … 
● sudo -l 

○ Sobre quin script aquest usuari té privilegis de root? 
○ Quines comandes executa aquest script? 
