És una app feta amb Python i Flask i que no funciona

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_b70d406ae666024b.png)  

Reddit ha bloquejat la app, però per el challenge ens serveix ja que farem un atac d’URL. Ara hauríem de veure una aplicació sobre gats.

  

Com tots els challenge que hem fet fins ara està amb Docker:

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_4bb2b51a8a98386d.png)  

Anem a veure el fitxer Dockerfile i busquem info sobre la flag i cap al final del document veiem que la flag està a una variable d’entorn i a més sabem el nom que té aquesta variable:

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_8148ea054512a3b8.png)  


Ara analitzarem el codi de la app per veure com funciona. Primer obrim el run.py:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_bf48b94fc61078ea.png)  

Veiem com al app fa un run per totes les IP’s de la màquina per aquest port concret, per tant nosaltres hem de fer una petició cap aquí per poder accedir a les variables d’entorn.

``app.run(host='0.0.0.0', port=1337)``

A aquest fitxer no hi ha més informació, anem ara a application → blueprints i anem al fitxer routes.py que és un fitxer de Flask:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_d4069eb12c0d667a.png)  


Veiem les 3 redireccions que es fan:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_f255732cbf2a7935.png)  


Però anem a la ruta on hi ha les rutes d’entorn, i veiem com les carrega i les mostra per pantalla, aquest serà l’endpoint que voldrem atacar:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_ebae30c3319cd4de.png)  

  

El nostre objectiu és accedir a la IP + port + /debug_environment

  
```
`@debug.route('/environment', methods=['GET'])

@is_from_localhost

def debug_environment():

environment_info = {

'Environment variables': dict(os.environ),

'Request headers': dict(request.headers)

}
````
  

El que fa aquesta funció debug/environment és carregar les variables d’entorn i mostrarles per pantalla a més de carregar els headers.


També veiem que carrega la funció: @is_from_localhost i si aquesta funció dona no no s’executa, si dona sí si que s’executa.


Anem a buscar què fa aquesta funció doncs i la trobem al fitxer util.py:


```
`def is_from_localhost(func):

@functools.wraps(func)

def check_ip(*args, **kwargs):

if request.remote_addr != '127.0.0.1':

return abort(403)

return func(*args, **kwargs)

return check_ip`
```

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_d284541565ac478.png)  

  
Fa un chek_ip i diu que si el request no rpové del localhost retorni un 403, per tant en teoria haurem d’entrar per 127.0.0.1

  
Si tornem al fitxer routes.py veiem que / carrega la funció proxy que és el que no està funcionant:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_db28203f1f2bc919.png)  

  

```
`@proxy_api.route('/', methods=['GET', 'POST'])

def proxy():

url = request.args.get('url')`
```

  

```
`if not url:

cat_meme_subreddits = [

'/r/cats/',

'/r/catpictures',

'/r/catvideos/'

]`
```

  

``random_subreddit = random.choice(cat_meme_subreddits)``

Veiem també que la url que carrega la posa aquí:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_963f8ff54d0d85cd.png)  

  
``SITE_NAME`` és una variable:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_f58599b157c479cc.png)  

  

No podem modificar la part de reddit.com però sí la següent, per tant haurem de fer un bypass de combinació i farem que l’usuari sigui reddit.com, que es pensarà que és l’usuari que es vol connectar al servidor.

  
Redirigim la connexió de reddit.com al que posem després de @. Ens permet fer el bypass l’@. La nostra arma és posar això:

``83.136.249.57:39803/?url=/127.0.0.1:1337/debug/environment``


Al ser la petició interna seva el 127 es fa al servidor. Però, aquesta IP està restringida:

  

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_a48a40653f0c85e1.png)  


Però si ho provem amb 0.0.0.0 sí que ens funciona:

  

``http://83.136.249.57:39803/?url=@0.0.0.0:1337/debug/environment``



![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_606d5b8c5b747646.png)  

I ja tenim al flag: **HTB{fl4gs_4s_4_S3rv1c3}**

![](file:///C:/Users/pmpol/AppData/Local/Temp/lu18992x90bty.tmp/lu18992x90bu2_tmp_97d90c4d549fd9a9.png)
