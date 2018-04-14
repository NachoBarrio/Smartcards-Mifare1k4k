card = new Card();
atr = card.reset(Card.RESET_COLD);
var completar = new ByteString("FF FF FF FF FF FF FF FF",HEX);
crypto = new Crypto();
deskey = new Key();
//print(atr);
//Carga la clave en el lector. ff ff ff ff ff ff en la posicion 0.
resp = card.plainApdu(new ByteString("FF 82 20 00 06 FF FF FF FF FF FF", HEX));
print(card.SW.toString(16));
//
//Lee el serial number de la tarjeta
resp = card.plainApdu(new ByteString("FF CA 00 00 04", HEX));
print("SERIAL NUMBER: " + resp);
print(card.SW.toString(16));
print();


var kEmisor = new ByteString("00 01 02 03 04 05 06 07",HEX);
var kViaje  = new ByteString("08 09 0A 0B 0C 0D 0E 0F",HEX);
var LastKey = kEmisor.concat(kViaje);
deskey.setComponent(Key.DES, LastKey);
var VI = new ByteString("00 00 00 00 00 00 00 00", HEX);

// inicio comprobador
// Leer MAC
//SE AUTENTICA CON EL BLOQUE 4 del SECTOR 1

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 04 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
var resp = card.plainApdu(new ByteString("FF B0 00 04 10", HEX));
var MACc = resp.bytes(12,4);
print("MAC obtenida: "+MACc);




//SE AUTENTICA CON EL BLOQUE 9 del SECTOR 2
//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 09 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer monedero
var resp = card.plainApdu(new ByteString("FF B0 00 09 10", HEX));
var monederoCifrado = resp.bytes(0,8);
var descifrado = crypto.decrypt(deskey,Crypto.DES_CBC, monederoCifrado,VI);
print("descifrado: "+descifrado.toString());
//comprobar MAC
var monederoConcatRelleno = descifrado.pad(Crypto.ISO9797_METHOD_2, true);
var monederoConcatCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, monederoConcatRelleno, VI);
var MAC = monederoConcatCifrado.right(8).left(4);
print("MAC comparada con MACc "+MAC+"<---->"+MACc);

//Mostrar valor monedero
var dinero = descifrado.bytes(2,2).toSigned();
print("Valor actual del monedero: "+dinero.toString());