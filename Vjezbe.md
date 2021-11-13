# ARP- spoofing

Klonirani git repozitorij: git clone https://github.com/mcagalj/SRP-2021-22

U direktoriju pokrecemo bash script: sh./start/sh

Udimo u docker container s naredbom docker exec -it station-1 bash i pingamo station - 2 sa ping station-2

Dohvati containerovu IP i Mac adresu sa naredbom ipconfig

station-1: 

IP: 172.21.02

ETH: 00:02

station-2:

IP: 172.21.04

ETH: 00:04

evil-station:

IP: 172.21.03

ETH: 00:03

Zapocinjemo razgovor izmedu dva stationa. Na Station-2 unosimo komandu: netstat -l -p 8000, a na Station-1 komandu: netstat station-2 8000. Time je uspostavljena komunikacija izmedu te dvije postaje.

Nakon toga ulazimo u evil-station i koristimo naredbe tcpdump za 'prisluskivanje' razgovora, arpspoof -t station-1 -r station-2.

Kad to napravimo unesemo naredbu:  tcpdump -XA station-1 and not arp.

Za blokiranje komunikacije izmedu te dvi postaje: echo 0 > /proc/sys/net/ipv4/ip_forward.

# Vjezba 2

Za pripremu *crypto* izazova, odnosno enkripciju korištena je Python biblioteka `[cryptography](https://cryptography.io/en/latest/)`. *Plaintext* koji student treba otkriti enkriptiran je korištenjem *high-level* sustava za simetričnu enkripciju iz navedene biblioteke - Fernet.

Fernet koristi sljedeće *low-level* kriptografske mehanizme:

- AES šifru sa 128 bitnim ključem
- CBC enkripcijski način rada
- HMAC sa 256 bitnim ključem za zaštitu integriteta poruka
- Timestamp za osiguravanje svježine (*freshness*) poruka

U ovom dijelu vježbi, najprije ćemo se kratko upoznati sa načinom na koji možete enkriptirati i dekriptirati poruke korištenjem Fernet sustava.

Rad u Pythonu(v3).

- instaliranje kriptografijskog modula i pokretanje Python-a:

`$ pip install cryptography$ python`

Prvi koraci sa Fernetom.

from cryptography.fernet import Fernet

PLAINTEXT = b"Hello world"

key = Fernet.generate_key()

fernet = Fernet(key=key)

ciphertext = fernet.encrypt(PLAINTEXT)

deciphertext = fernet.decrypt(ciphertext)

print(f"{ciphertext}\n : \n{deciphertext}")

Nakon toga u folderu pronalazimo file cije ime odgovara nasem hashiranom imenu kojeg dobijemo gornjim kodom

from cryptography.hazmat.primitives import hashes

def hash(input):
if not isinstance(input, bytes):
input = input.encode()

```
digest = hashes.Hash(hashes.SHA256())
digest.update(input)
hash = digest.finalize()

return hash.hex()

```

filename = hash('ime_prezime') + ".encrypted"

```
if __name__ == "__main__":
    print(hash("lozano_strkalj_william"))
```

Metodom brute-forceom saznajemo enkripcijski kljuc entropije 22 bita

import base64
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

def hash(input):
if not isinstance(input, bytes):
input = input.encode()

```
digest = hashes.Hash(hashes.SHA256())
digest.update(input)
hash = digest.finalize()

return hash.hex()

```

def test_png(header):
if header.startswith(b"\211PNG\r\n\032\n"):
return True

def brute_force():
filename = "william_challenge.encrypted"

with open(filename, "rb") as file:
ciphertext = file.read()

```
ctr = 0
while True:
    key_bytes = ctr.to_bytes(32, "big")
    key = base64.urlsafe_b64encode(key_bytes)

    if not (ctr + 1) % 1000:
        print(f"[*] Keys tested: {ctr + 1:,}", end="\\r")

    try:
        plaintext = Fernet(key).decrypt(ciphertext)

        header = plaintext[:32]
        if test_png(header):
            print(f"[+] KEY FOUND: {key}")
            # Writing to a file
            with open("BINGO.png", "wb") as file:
                file.write(plaintext)
            break

    except Exception:
        pass

    ctr += 1

```

if **name** == "**main**":
#hash value = hash("lozano_strkalj_william")
#print (hash_value)
brute_force()
