# hash_demo.py – benötigt nur die Standardbibliothek
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


print("")
print("Hashfunktion")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

#  Deterministisch: gleiche Eingabe -> gleicher Hash
print(sha256("Hallo Welt"))
print(sha256("Hallo Welt"))

#  Feste Länge, egal wie lang die Eingabe ist
print(len(sha256("a")), len(sha256("a" * 1_000_000)))   # beide 64 Hex-Zeichen

#  Lawineneffekt: 1 Zeichen anders -> völlig anderer Hash
original = sha256("Überweise 100 Euro an Alice")
veraendert = sha256("Überweise 900 Euro an Alice")
print(original)
print(veraendert)
diff_bits = bin(int(original, 16) ^ int(veraendert, 16)).count("1")
print(f"Unterschiedliche Bits: {diff_bits} von 256")     # ca. 128

#  Integritätsprüfung einer Datei
def file_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

#  Warum man Passwörter nicht einfach hasht: Salt + langsame Funktion
salt = os.urandom(16)
pw_hash = hashlib.pbkdf2_hmac("sha256", b"geheim123", salt, 600_000)
print("PBKDF2:", pw_hash.hex())

'''
---------------------------------------------------------
'''

print("")
print("digitale Signatur")



#  Digitale Signatur

# Lehrbeispiel, NICHT für echte Anwendungen


# --- Schlüsselerzeugung ---
p, q = 61, 53
n = p * q                    # 3233  (Modulus, öffentlich)
phi = (p - 1) * (q - 1)      # 3120
e = 17                       # öffentlicher Exponent
d = pow(e, -1, phi)          # 2753  privater Exponent
print(f"Öffentlicher Schlüssel: (e={e}, n={n})")
print(f"Privater Schlüssel:     (d={d}, n={n})")

def hash_to_int(msg: str) -> int:
    # Hash auf Zahlenbereich < n reduzieren (nur wegen des kleinen n)
    return int(hashlib.sha256(msg.encode()).hexdigest(), 16) % n

# --- Signieren (mit privatem Schlüssel) ---
def sign(msg: str) -> int:
    return pow(hash_to_int(msg), d, n)

# --- Verifizieren (mit öffentlichem Schlüssel) ---
def verify(msg: str, sig: int) -> bool:
    return pow(sig, e, n) == hash_to_int(msg)

nachricht = "Vertrag: Bob zahlt Alice 100 Euro"
sig = sign(nachricht)
print("Signatur:", sig)
print("Echt?        ", verify(nachricht, sig))                                  # True
print("Manipuliert? ", verify("Vertrag: Bob zahlt Alice 900 Euro", sig))        # False


'''
Signiert wird nicht die Nachricht selbst, sondern ihr Hash. 
So kommen beide Themen zusammen.
Nur wer den privaten Schlüssel d hat, kann signieren. Prüfen kann jeder mit e und n.
Wird die Nachricht verändert, schlägt die Prüfung fehl (Integrität). 
Der Absender kann die Signatur später nicht abstreiten (Nichtabstreitbarkeit).
'''


'''
-------------------------------------------------------
'''

print("")
print("echte Signatur")


#  Echte Signatur mit Bibliothek
#ED25519 und RSA-PSS

msg = b"Rechnung Nr. 4711: 250,00 EUR"

# --- Ed25519 (modern, schnell, kurze Schlüssel) ---
priv = ed25519.Ed25519PrivateKey.generate()
pub = priv.public_key()
sig = priv.sign(msg)
print("Ed25519-Signatur:", sig.hex(), f"({len(sig)} Bytes)")

for m in (msg, b"Rechnung Nr. 4711: 950,00 EUR"):
    try:
        pub.verify(sig, m)
        print("gültig:  ", m)
    except InvalidSignature:
        print("UNGÜLTIG:", m)

# --- RSA-PSS mit SHA-256 ---
rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=3072)
rsa_sig = rsa_priv.sign(
    msg,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
rsa_priv.public_key().verify(
    rsa_sig, msg,
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)
print("RSA-PSS-Signatur gültig,", len(rsa_sig), "Bytes")

# Öffentlichen Schlüssel exportieren (z. B. zum Weitergeben)
print(pub.public_bytes(serialization.Encoding.PEM,
                       serialization.PublicFormat.SubjectPublicKeyInfo).decode())