import hashlib
import Crypto.Util.number

# Ejercicio 1

# El mensaje M sera de 1050 caracteres
message = "En el vasto lienzo de la existencia, cada uno de nosotros es un pincel que agita los colores de la vida. Nuestros trazos, aunque efímeros, dejan una huella indeleble en el lienzo del tiempo. Cada acto, cada palabra, cada elección es una pincelada que define nuestra historia. En este mar de posibilidades, navegamos con la esperanza de encontrar nuestro propósito, de tejer un tapiz de significado en medio de la vastedad del universo. A veces, los colores se desvanecen y la oscuridad amenaza con invadir nuestro lienzo, pero en esos momentos recordamos que somos los artistas de nuestra propia vida. Con determinación y coraje, tomamos el pincel y volvemos a pintar nuestro destino, llenándolo de luz y color. No importa cuán complejo sea el diseño, cada trazo cuenta una historia única, cada color refleja una emoción genuina. Así que pintemos con pasión, con amor, con valentía. Permitamos que nuestras obras resplandezcan en la galería del tiempo, inspirando a otros a pintar sus propios destinos con la misma intensidad. En este lienzo llamado."
#print("Logitud del mensaje: ", len(message))

# Hashear nuestro mensaje
hash = hashlib.sha256(message.encode()).hexdigest()
hashInt = int(hash, 16)
#print('Mensaje hasheado: ',hashInt)

# Dividir en 128 el mensaje
# Ciclo para dividr el mensaje en 128
messageDivided = [message[i:i+128] for i in range(0, len(message), 128)]
#print('Mensaje dividido: ' , messageDivided)

# Generar llaves
bits = 1024

# Obtener llave de Bob
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Llave publica Bob
nB = pB * qB
#Calcular indicador Euler Phi
phiB = (pB - 1) * (qB - 1)
#Euler
e = 65537
# Llave privada Bob
dB = Crypto.Util.number.inverse(e, phiB)


# Obtener llave de Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Llave publica Alice
nA = pA * qA
#Calcular indicador Euler Phi
phiA = (pA - 1) * (qA - 1)
#Euler
e = 65537
# Llave privada Alice
dA = Crypto.Util.number.inverse(e, phiA)

#Alice cifrara los mensajes con llave publica de bob
messagesAlice = []
for h in messageDivided:
    m = int.from_bytes(h.encode('utf-8'), "big")
    encryptedMessage = pow(m, e, nB)
    messagesAlice.append(encryptedMessage)

#print('Mensajes encriptados: ', messagesAlice)
a = 1
print(a)
#Descifrar mensajes con llave privada de Bob
messagesBob = []
for i in messagesAlice:
    decryptedMessage = pow(i, dB, nB)
    decryptedMessage_bytes = decryptedMessage.to_bytes((decryptedMessage.bit_length() + 7) // 8, byteorder='big')
    messagesBob.append(decryptedMessage_bytes.decode('utf-8'))


print('Mensajes BOB:', messagesBob)
# Unir partes del mensaje
completeDecryptedMessage = ''.join(messagesBob)

print("Mensaje desencriptado", completeDecryptedMessage)

# Hashear nuestro mensaje descencriptado
hashRecibido = hashlib.sha256(completeDecryptedMessage.encode()).hexdigest()
hashIntRecibido = int(hashRecibido, 16)
print('Mensaje hasheado: ',hashIntRecibido)

if hashRecibido == hash:
    print("El hash es igual, el mensaje llego perfectamente.")

