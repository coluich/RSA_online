import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def genera_coppia_chiavi_rsa():
    chiave_privata = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return chiave_privata, chiave_privata.public_key()

def AES_gen():
    return Fernet.generate_key()

def salva_chiave(tipo_chiave=None, chiave=None, nome_file='RSA_KEY.pem'):
    if tipo_chiave == "D":
        with open(nome_file, 'wb') as f:
            f.write(chiave.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    elif tipo_chiave == "E":
        with open(nome_file, 'wb') as f:
            f.write(chiave.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def carica_chiave_privata(nome_file='chiave_privata.pem'):
    return serialization.load_pem_private_key(
        open(nome_file, 'rb').read(),
        password=None,
        backend=default_backend())

def carica_chiave_pubblica(nome_file='chiave_pubblica.pem'):
    return serialization.load_pem_public_key(
        open(nome_file, 'rb').read(),
        backend=default_backend())

def E(messaggio, chiave_pubblica):
    testo_cifrato = chiave_pubblica.encrypt(
        messaggio.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return testo_cifrato

def D(testo_cifrato, chiave_privata):
    testo_decifrato = chiave_privata.decrypt(
        testo_cifrato,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return testo_decifrato.decode("utf-8")

def O(messaggio, chiave_privata):
    firma = chiave_privata.sign(
        messaggio.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma

def F(firma, chiave_pubblica):
    try:
        # Verifica la firma con la chiave pubblica
        chiave_pubblica.verify(
            firma,
            messaggio.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Restituisci il testo originale in caso di verifica positiva
        return True
    except cryptography.exceptions.InvalidSignature:
        # Restituisci False in caso di verifica negativa
        return False

def AES(messaggio, key):
    return Fernet(key).encrypt(messaggio.encode("utf'8"))

def SEA(testo_cifrato, key):
    return Fernet(key).decrypt(testo_cifrato)
    

chiave_privata, chiave_pubblica = genera_coppia_chiavi_rsa()
messaggio = "Ciao, questo è un messaggio segreto."

print("Messaggio originale:", messaggio)

firma = O(messaggio, chiave_privata)
print("Messaggio firmato:", firma)

risultato_verifica = F(firma, chiave_pubblica)
print(f"\nRisultato verifica: {risultato_verifica}")

key = AES_gen()
messaggio_cifrato = AES(messaggio, key)
print("cifrato",messaggio_cifrato.decode("utf-8"))

messaggio = SEA(messaggio_cifrato, key).decode("utf-8")
print("decifrato: ",messaggio)