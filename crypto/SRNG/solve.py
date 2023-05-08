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

