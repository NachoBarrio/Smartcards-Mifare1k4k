card = new Card();
atr = card.reset(Card.RESET_COLD);

//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();

print("Constante Km");
var Kt = new ByteString("88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77", HEX);

print("Constante Kc");
var Kc = new ByteString("CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB", HEX);

deskey.setComponent(Key.DES, Kc);

//Escribir datos tarjeta en sector 01
//SE AUTENTICA CON EL BLOQUE 4 del SECTOR 1
//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 04 60 00", HEX));
//print("Código SW: " + card.SW.toString(16));

//ESCRITURA DEL BLOQUE 4
resp = card.plainApdu(new ByteString("FF D6 00 04 10 DD 04 DC 04 DF 04 DD 04 DC 04 DF 04 DC 04 DF 04", HEX));
//
print("Código SW: " + card.SW.toString(16));