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

# Vjezba 3

## Kao prvi zadatak moramo kreirati tekstualnu datoteku zasticenog integriteta pomocu HMAC mehanizma i python biblioteke criptography

Kreiranje datoteke sa tajnom porukom i citanje te poruke

from cryptography.hazmat.primitives import hashes

def main():
with open("./message.txt", "rb") as file:
content = file.read()
print(content)

if **name** == "**main**":
main()

Kreiramo funkciju za izracun MAC koda, sa definiranim kljucem kojeg koristimo

from cryptography.hazmat.primitives import hashes, hmac

def generate_mac(key, message):
if not isinstance(message, bytes):
message = message.encode()

```
h = hmac.HMAC(key, hashes.SHA256())
h.update(message)
signature = h.finalize()
return signature
```

Kreiramo MAC kod pomocu prethodno definirane funkcije

def main():
secret = b"My super secret"

```
with open("./message.txt", "rb") as file:
    content = file.read()

mac = generate_mac(secret, content)
print(mac.hex())
```

Validiramo MAC kod funkcijom  is_mac_valid()

def verify_mac(key, message, mac):
if not isinstance(message, bytes):
message = message.encode()

```
h = hmac.HMAC(key, hashes.SHA256())
h.update(message)
try:
    h.verify(mac)
except InvalidSignature:
    return False
else:
    return True
```

U funckiji main zapisemo kod za validaciju MAC-a te ga izcitava iz datoteke message.sig

with open("./message.sig", "rb") as file:
mac = file.read()

```
if verify_mac(secret, content, mac):
    print("Valid MAC")
else:
    print("Invalid MAC")
```

## Za drugi zadatak moramo odrediti ispravnu sekvenciju transakcija autenticnih poruka. Datoteke dohvacamo iz foldera sa MAC izazovima koji nam je na raspolaganju na lokalnoj mrezi koju koristimo na satu

Downloadanje samih datoteka

wget.exe -r -nH -np --reject "index.html*" [http://a507-server.local/challenges/](http://a507-server.local/challenges/)<lozano_strkalj_william>/

Kljuc za provjeru MAC-a je "<lozano_strkalj_william>".encode()

Kreiramo funkciju za dohvacanje cijelog "relative patha" do nase datoteke

def get_folder(name):
return f"./challenges/lozano_strkalj_william/mac_challenge/{name}"

Za generaciju i validiranje MAC koda koristimo funkcije generate_mac i verify_mac iz proslog zadatka

Uz pomoc for petlje iteriramo preko svih 10 datoteka kako bi im procitali poruke i MAC vrijednosti

for i in range(1, 11):
msg_filename = f"order_{i}.txt"
sig_filename = f"order_{i}.sig"

```
    with open(get_folder(msg_filename), 'rb') as file:
        message = file.read()

    with open(get_folder(sig_filename), 'rb') as file:
        sig = file.read()

    is_authentic = verify_mac(KEY, sig, msg)
    print(f'Message {message.decode():>45} {"done" if is_authentic else "exception has occured":<6}')
```

Uz to provjeravamo jesu li datoteke poredane po redu funkcijom check_timestamp

def check_tstamp(message):
return datetime.strptime(message.decode()[-17:-1], "%Y-%m-%dT%H:%M")

Ovu funkciju pozivamo na kraj petlje

Na kraju sortiramo datoteke po timestampu i provjeravamo jeli sortirani redoslijed jednak nesortiranom

Ako nisu ispisujemo tocan redoslijed

correct_order = sorted(order, key=lambda x: x[0])
correct_order_idxs = [item[1] for item in correct_order]

if correct_order_idx != [i for i in range(1, 11)]:
print(f"Order incorrect.")
print(f"The correct order of messages is: {[item[1] for item in correct_order]}")

## Za treci zadatak moramo od dvije ponudene slike odrediti koja je od njih autenticna, svaka slika je potpisana privatnim kljucem, a javni kljuc downloadamo na lokalnom serveru.

Kod za citanje i provjeru autenifikacije slike glasi:

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

#Ucitavanje javnog kljuca i deserializacija

```
PUBLIC_KEY_PATH = "./public_key_challenge/public.pem"

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        public_key = serialization.load_pem_public_key(
            data=f.read(),
            backend=default_backend(),
        )
        return public_key
```

#Provjera ispravnosti digitalnog potpisa

```
def verify_signature_rsa(signature, message):
    PUBLIC_KEY = load_public_key()
    try:
        PUBLIC_KEY.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    else:
        return True
```

#Ostatak koda

```
signature1 = open("./public_key_challenge/image_1.sig", "rb")
image1 = open("./public_key_challenge/image_1.png", "rb")
if verify_signature_rsa(signature1.read(), image1.read()):
    print("Image 1 is AUTHENTIC")
else:
    print("Image 1 is NOT AUTHENTIC")
signature1.close()
image1.close()

signature2 = open("./public_key_challenge/image_2.sig", "rb")
image2 = open("./public_key_challenge/image_2.png", "rb")
if verify_signature_rsa(signature2.read(), image2.read()):
    print("Image 2 is AUTHENTIC")
else:
    print("Image 2 is NOT AUTHENTIC")
signature2.close()
image2.close()
```

# Vjezba 4

U ovoj vjezbi  usporedujemo klasicne (*brze*) kriptografske *hash* funkcije sa specijaliziranim (*sporim* i *memorijski zahtjevnim*) kriptografskim funkcijama za sigurnu pohranu zaporki i izvodenje enkripcijskih ključeva (*key derivation function (KDF)*).

Navedeni kod kojeg smo kopirali sadrzi funkcije za 

- Usporedbu *brzih* i *sporih* kriptografskih *hash* funkcija.
- Razumijevanje sustine pojmova *spore/brze* funkcije.
- Demonstraciju *memory-hard* funkcija.

```
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_itdef aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_itdef md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_itdef sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_itdef sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_itdef pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_itdef argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_itdef linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_itdef linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_itdef scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

Rezultat izvodenja koda je tablica sa prosjecnim vremenom izvodenja funkcija pokrenutih 100 puta

Na pojedinim funkcija primjenit ćemo metode iterativnog i memory-hard hashiranja.

Funkcije koje koristimo su:

HASH_MD5, HASH_SHA256, AES, Linux CRYPT 5k rounds, Linux CRYPT 10k rounds
