import hashlib
from Crypto.Util.number import getPrime, inverse
import Crypto.Random

def read_last_bytes(filename, num_bytes):
    with open(filename, "rb") as f:
        f.seek(-num_bytes, 2)
        return f.read(num_bytes)

#FIRMA INICIAL DE ALICE
# Generación de llaves para Alice
bits = 1024
pA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nA = pA * qA
phiA = (pA - 1) * (qA - 1)
e = 65537
dA = inverse(e, phiA)

# Firma digital de Alice
with open("NDA.pdf", "rb") as f:
    pdf_bytes = f.read()
    pdf_hash = int.from_bytes(hashlib.sha256(pdf_bytes).digest(), "big")
signatureAlice = pow(pdf_hash, dA, nA)
print("Hash de alice: ", pdf_hash)

#  Firma a bytes para añadirla al pdf
signatureBytesA = signatureAlice.to_bytes((signatureAlice.bit_length() + 7) // 8, byteorder="big")

# Agregar firma al final del archivo
with open("NDA.pdf", "ab") as f:
    f.write(signatureBytesA)

# VERIFICACIÓN AUTORIDAD Y FIRMA
# Conseguir la firma (los ultimos bits)
signatureBytes = read_last_bytes("NDA.pdf", 256)
signatureInt = int.from_bytes(signatureBytes, byteorder="big")

# Quitar firma del e¿archivo apra verificar el hash original
with open("NDA.pdf", "rb") as f:
    pdfBytesA = f.read()[:-256]
    pdfHashA = int.from_bytes(hashlib.sha256(pdfBytesA).digest(), "big")

print("Hash de AC:", pdfHashA)
# Verificación por AC con la llave pública de Alice
verifyA = pow(signatureInt, e, nA)
print("Es la firma de Alice? (AC):", verifyA == pdfHashA)

# Si es la firma, se remueve del archivo
with open("NDA.pdf", "wb") as f:
    f.write(pdfBytesA)

# Generación de llaves para AC
pAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
nAC = pAC * qAC
phiAC = (pAC - 1) * (qAC - 1)
eAC = 65537
dAC = inverse(eAC, phiAC)

# Firma de AC con la publica de AC
signatureAC = pow(pdfHashA, dAC, nAC)

# Agregamos la firma de AC al final del archivo
signatureBytesAC = signatureAC.to_bytes(
    (signatureAC.bit_length() + 7) // 8, byteorder="big"
)
with open("NDA.pdf", "ab") as f:
    f.write(signatureBytesAC)

# VERIFICACIÓN DE BOB
# Conseguir las firmas
signatureBytesB = read_last_bytes("NDA.pdf", 256)
signatureIntB = int.from_bytes(
    signatureBytesB, byteorder="big"
)

# Quitamos la firma del pdf para validar si es el mismo
with open("NDA.pdf", "rb") as f:
    pdfBytesB = f.read()[:-256]
    pdfHashB = int.from_bytes(hashlib.sha256(pdfBytesB).digest(), "big")
print("Hash de Bob:", pdfHashB)
verifyPdfB = pow(signatureAC, eAC, nAC)
print("Es el pdf original? ", verifyPdfB == pdfHashA)