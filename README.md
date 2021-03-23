# Generar clave publica/privada autofirmada para las pruebas con JWT

    fuente: https://stackoverflow.com/questions/38794670/how-to-sign-a-jwt-using-rs256-with-rsa-private-key

    openssl genrsa -out privateKey.pem 512
    openssl rsa -in privateKey.pem -pubout -out publicKey.pem