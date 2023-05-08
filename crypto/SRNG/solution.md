# SRNG

## Description

> Spooder Random Numbers Generator: This is not the challenge the world wants, and it's not the challenge the world need, but this is the challenge that the world gets.
>
> ncat -v --ssl srng.bsides.shellmates.club 443

## Write-Up

Checking the code given, we can see that this an encryption service that uses random generated numbers :

```py
#!/usr/bin/env python
# from flag import FLAG
FLAG= "shellmates{redacted}"

import time

class Spooder:
    def __init__(self):
         self.rand, self.i = int(time.time()), 2
         self.generate_random()

    def generate_random(self, m: int = 0x10ffff) -> int:
        self.rand = pow(self.i, self.rand, m)
        self.i = self.i + 1
        return self.rand

    def generate_padding(self, l: int = 0x101) -> str:
        padding = ''
        for i in range(self.generate_random(l)):
            padding += chr(self.generate_random(0xd7fb))
        return padding

spooder = Spooder()

def spooder_encryption(message: str) -> str:
    pad = spooder.generate_padding()
    message = ''.join([chr(ord(c) ^ spooder.generate_random(0xd7fb)) for c in message])
    cipher = pad + message
    return cipher

if __name__ == '__main__':

    welcome = f'''
               ▗▄▖ ▗▄▄▖ ▗▄ ▗▖  ▄▄
              ▗▛▀▜ ▐▛▀▜▌▐█ ▐▌ █▀▀▌
              ▐▙   ▐▌ ▐▌▐▛▌▐▌▐▌
               ▜█▙ ▐███ ▐▌█▐▌▐▌▗▄▖
                 ▜▌▐▌▝█▖▐▌▐▟▌▐▌▝▜▌
              ▐▄▄▟▘▐▌ ▐▌▐▌ █▌ █▄▟▌
               ▀▀▘ ▝▘ ▝▀▝▘ ▀▘  ▀▀
    \n
    This is not the RNG the world wants, and it's not the RNG the world need, but this is the RNG that the world gets.
    Welcome to the Spooder Random Number Generator, or special random number generator.
    It can generate random numbers like this: {', '.join([str(spooder.generate_random()) for _ in range(spooder.generate_random(121))])}.
    It can also generate random strings like this: {spooder.generate_padding(53)}.
    You can also use it to encrypt secrets like this: {spooder_encryption(FLAG).encode().hex()}.
    Here is a free trial:
    1. Generate random string.
    2. Generate random number.
    3. Encrypt.
    '''

    print(welcome)
    tries = spooder.generate_random(7)
    print(f'You have {tries} tries .')
    for _ in reversed(range(tries)):
        choice = input('Choose wisely:\n\t> ')
        if choice == '1':
            print(spooder.generate_padding(11))
        elif choice == '2':
            print(spooder.generate_random(101))
        elif choice == '3':
            print(spooder_encryption(input('what do you want to encrypt?\n\t> ')))
        else:
            exit(0)
```

We can see that the seed used to start the random generation is based on the execution time, and we can find that there is a specific number of random operations before crypting the flag (which is represented by the i attribute of spooder) :

```

new random : 1
i : 201
You have 1 tries .

...

new random : 1
i : 227
You have 1 tries .

...

new random : 2
i : 170
You have 2 tries .

...

new random : 4
i : 183
You have 4 tries .

...

new random : 5
i : 333
You have 5 tries .
```

Also the functions available for generation :

- `generate_random()` is one random
- `generate_padding()` is one random N + N times random

So, to solve this challenge, we need to extract the seed or an intermediary random number to continue the sequence, this is necessary in order to guess the values sused to encrypt the flag.

Note that the encryption is based on a simple `xor`, so the decryption function is the same as the encryption one :

```py
def spooder_encryption(message: str) -> str:
    pad = spooder.generate_padding()
    message = ''.join([chr(ord(c) ^ spooder.generate_random(0xd7fb)) for c in message])
    cipher = pad + message
    return cipher
```

In our case, we will generate the time (with a certain precision) at the execution time, verify the sequence, and use it to decrypt the flag.

```py
#! /usr/bin/python3


from pwn import *
import time

class Spooder:
    def __init__(self, seed: int = int(time.time()), precision: int = 0.1):
         self.rand, self.i = seed - precision, 2
         self.generate_random()

    def generate_random(self, m: int = 0x10ffff) -> int:
        self.rand = pow(self.i, self.rand, m)
        self.i = self.i + 1
        return self.rand

    def generate_padding(self, l: int = 0x101) -> str:
        padding = ''
        for i in range(self.generate_random(l)):
            padding += chr(self.generate_random(0xd7fb))
        return padding
    
    def generate_padding_flag_encryption(self, l: int = 0x101) -> str:
        padding = ''
        padding_length = self.generate_random(l)
        for i in range(padding_length):
            padding += chr(self.generate_random(0xd7fb))
        return padding, padding_length

def spooder_encryption(message: str) -> str:
    pad = spooder.generate_padding()
    message = ''.join([chr(ord(c) ^ spooder.generate_random(0xd7fb)) for c in message])
    cipher = pad + message
    return cipher


HOST = 'srng.bsides.shellmates.club'
PORT = 443

p = remote(HOST, PORT, ssl=True)

seed = int(time.time())

# SRNG symbol
for i in range(9) :
    p.recvline()

# Data
for i in range(3) :
    p.recvline()

# This is for random numbers
random_numbers = p.recvline().decode().split(": ")[1].strip(".\n").split(", ")
# print(random_numbers)
# print(len(random_numbers))

# This is for random strings
random_strings = p.recvline().decode().split(": ")[1].strip(".\n")
# print(random_strings)
# print(len(random_strings))
random_strings = random_strings.encode()
# print(len(random_strings))

# This is for the flag
flag_encrypted = p.recvline().decode().split(": ")[1].strip(".\n")
# print(flag_encrypted)

# Menu
# for i in range(6) :
#     p.recvline()

# p.sendlineafter(b'Choose wisely:\n\t> ', b'2')

# p.interactive()


for i in range(1, 100, 1):
    spooder = Spooder(seed, int(0.1*i))

    # First check
    if spooder.generate_random(121) != len(random_numbers):
        continue

    if [str(spooder.generate_random()) for _ in range(len(random_numbers))] != random_numbers:
        continue

    # second check
    if spooder.generate_padding(53) != random_strings.decode() :
        continue

    print(f"seed found : {seed - 0.1*i}")

    byte_str = bytes.fromhex(flag_encrypted)
    flag_encrypted_unhexed = byte_str.decode()

    print(flag_encrypted_unhexed)

    padding, padding_length = spooder.generate_padding_flag_encryption()

    # Another check
    if not (padding in flag_encrypted_unhexed) :
        continue

    flag_encrypted_unhexed = flag_encrypted_unhexed[padding_length: ]

    flag = [chr(ord(c) ^ spooder.generate_random(0xd7fb)) for c in flag_encrypted_unhexed]

    print(flag)

    # Instead of this, catch exception of unicode and try another seed
    break
```

We get :

```
[+] Opening connection to srng.bsides.shellmates.club on port 443: Done
seed found : 1683318247.0
턈䥢嫴ᤷ뿄尦㣨潉쁍刏㵵펧ೊ뙡ඳ仟斃薷蒙ꑀ礪㖾꩟╮虩뢋汲뮁錯骂삢㍤巩㙻䣼嘅凰塔᧵ꛛ儉랑攗姘ӺᗋỆ⾉帍키㷧䂇촄㜤ط畉ᣟᎻ땚륙ƒ㸾㔷肆᥯锆鱀噝捗抝芜鬎咂홋㠀༉瞔ម膟Ṑⲡ埊ⴹ霞퇈蒢삄뉳ᵛ᫞ꀰ譎䉇䦰㥼̻㌕⃉쨁’ቃ暝䍅ǣ㻫潈哗졹ꀣ纳艐箣焵勽棭沼꒚绽㕸≃᯻ꂬ㲏㿚唞ꀕ꘻푾叻㻊⑚䜒岹兜샊禰ᠷ㺨傘战齉㍍ᙚ豥࿐⸢꽘겗ꄎⷧ湡锃檊➩ꕷ騮㮜焴Ä郵祾䋾팄㑠묖͐츤칥㳱⟉蹿㇊
['s', 'h', 'e', 'l', 'l', 'm', 'a', 't', 'e', 's', '{', '5', 'p', '0', '0', 'd', '3', 'R', '_', 'F', 'l', '4', 'g', '_', 'f', '0', 'r', '_', 's', 'P', 'o', 'o', 'D', 'e', 'R', '_', 'c', 'H', '4', 'l', 'L', '3', 'n', 'g', 'e', '}']
[*] Closed connection to srng.bsides.shellmates.club port 443
```

```
In [1]: li = ['s', 'h', 'e', 'l', 'l', 'm', 'a', 't', 'e', 's', '{', '5', 'p', '0', '0', 'd', '3', 'R', '_', 'F', 'l', '4', 'g', '_', 'f', '0', 'r', '_', 's', 'P', 'o', 'o', 'D', 'e', 'R', '_', 'c', 'H', '4', 'l', 'L', '3', 'n', 'g', 'e'
   ...: , '}']

In [3]: ''.join(li)
Out[3]: 'shellmates{5p00d3R_Fl4g_f0r_sPooDeR_cH4lL3nge}'
```

Note That it is a matter of precision, you can add instead of a break, if there is a unicode exception, you continue to try another seed.

## Flag

shellmates{5p00d3R_Fl4g_f0r_sPooDeR_cH4lL3nge}