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
 
//Sector usuario bloque 8 sector 2

var codFechaDia = "01";
var codFechaMes = "01";
var codFechaAnio = "2001";
var codHora = "00";
var codMin = "00";
var codTrans = "00 01";

var usuarioConcat = new ByteString(codFechaDia+codFechaMes+codFechaAnio+
codHora+codMin+codTrans, HEX);
var usuarioConcatRelleno = usuarioConcat.pad(Crypto.ISO9797_METHOD_2, true);
var usuarioConcatCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, usuarioConcatRelleno, VI);
var MAC = usuarioConcatCifrado.right(8).left(4);
print("pintar mac: "+MAC);

//Sector mac bloque 4 sector 1

//SE AUTENTICA CON EL BLOQUE 4 del SECTOR 1

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 04 60 00", HEX));
//print("Código SW: " + card.SW.toString(16));

//ESCRITURA DEL BLOQUE 4
resp = card.plainApdu(new ByteString("FF D6 00 04 10 DD 04 DC 04 DF 04 DD 04 DC 04 DF 04"+MAC,HEX)); 

//SE AUTENTICA CON EL BLOQUE 8 del SECTOR 2
//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 08 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Escribe los datos personales en el sector 2 bloque 8 rellenando el bloque
resp = card.plainApdu(new ByteString("FF D6 00 08 10", HEX).concat(usuarioConcatCifrado).concat(completar));
print("Código SW: " + card.SW.toString(16));

//Sector monedero bloque 9 sector 2
var codEmisor = "C0 D0";
var valorInicial = "00 08"  //8 porque es igual a 10 viajes
var valorMax = "3A 98" ; //15000
var codPago = "00 01";
var monederoConcat = new ByteString(codEmisor+valorInicial+valorMax+codPago, HEX);
var monederoConcatRelleno = monederoConcat.pad(Crypto.ISO9797_METHOD_2, true);
var monederoConcatRelleno = crypto.encrypt(deskey, Crypto.DES_CBC, monederoConcatRelleno, VI);
//SE AUTENTICA CON EL BLOQUE 9 del SECTOR 2
//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 09 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Escribe los datos personales en el sector 2 bloque 9 rellenando el bloque
resp = card.plainApdu(new ByteString("FF D6 00 09 10", HEX).concat(monederoConcatRelleno).concat(completar));
print("Código SW: " + card.SW.toString(16));


