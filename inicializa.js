card = new Card();
atr = card.reset(Card.RESET_COLD);

//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();

print("Constante Kt");
var Kt = new ByteString("CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB", HEX);

print("Constante Km");
var Km = new ByteString("88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77", HEX);

deskey.setComponent(Key.DES, Kt);

//Construir TLVS - etiqueta - tamaño datos - datos + relleno
//nombre reserva 2 sectores
var nombre = new ByteString("Ignacio Barrio Santos",ASCII);
var HC1 = "C1";
var LC1 = (nombre.length).toString(16);
print("prueba: "+LC1+","+LC1.length);
if(LC1.length < 2){
	LC1 = "0" + LC1;
}
while (nombre.length < 30){
	nombre = nombre.concat(new ByteString("FF",HEX));
}
var TLVC1 = new ByteString(HC1 + LC1 + nombre,HEX);

//tarjeta reservan 2 sectores
var tarjeta = new ByteString("1111222233334444",ASCII);

var HC2 = "C2";
var LC2 = (tarjeta.length).toString(16);
if(LC2.length < 2){
	LC2 = "0" + LC2;
}
while (tarjeta.length < 30){
	tarjeta = tarjeta.concat(new ByteString("FF",HEX));
}
var TLVC2 = new ByteString(HC2 + LC2 + tarjeta,HEX);
print("prueba TLVC2: "+TLVC2);
//fecha reserva 1 sector
var fecha = new ByteString("0419",ASCII);

var HC3 = "C3";
var LC3 = (fecha.length).toString(16);
if(LC3.length < 2){
	LC3 = "0" + LC3;
}
while (fecha.length < 14){
	fecha = fecha.concat(new ByteString("FF",HEX));
}
var TLVC3 = new ByteString(HC3 + LC3 + fecha,HEX);

print("nombre:" + TLVC1.length + ","+ TLVC1);
print("tarjeta:" + TLVC2.length + ","+ TLVC2);
print("fecha:" + TLVC3.length + ","+ TLVC3);

// por haber usado la tarjeta para el ejercicio del bus, se salvan los datos a partir del sector06
//SE AUTENTICA CON EL BLOQUE 18 del SECTOR 6
	//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 18 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
	
resp = card.plainApdu(new ByteString("FF D6 00 18 10", HEX).concat(TLVC1.left(16)));
print("Código SW: " + card.SW.toString(16));

// por haber usado la tarjeta para el ejercicio del bus, se salvan los datos a partir del sector06
//SE AUTENTICA CON EL BLOQUE 19 del SECTOR 6
	//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 19 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
	
resp = card.plainApdu(new ByteString("FF D6 00 19 10", HEX).concat(TLVC1.right(16)));
print("Código SW: " + card.SW.toString(16));

// por haber usado la tarjeta para el ejercicio del bus, se salvan los datos a partir del sector06
//SE AUTENTICA CON EL BLOQUE 1A del SECTOR 6
	//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1A 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
	
resp = card.plainApdu(new ByteString("FF D6 00 1A 10", HEX).concat(TLVC2.left(16)));
print("Código SW: " + card.SW.toString(16));

// por haber usado la tarjeta para el ejercicio del bus, se salvan los datos a partir del sector06
//SE AUTENTICA CON EL BLOQUE 1C del SECTOR 7
	//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1C 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
	
resp = card.plainApdu(new ByteString("FF D6 00 1C 10", HEX).concat(TLVC2.right(16)));
print("Código SW: " + card.SW.toString(16));

// por haber usado la tarjeta para el ejercicio del bus, se salvan los datos a partir del sector06
//SE AUTENTICA CON EL BLOQUE 1D del SECTOR 7
	//
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1D 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
	
resp = card.plainApdu(new ByteString("FF D6 00 1D 10", HEX).concat(TLVC3));
print("Código SW: " + card.SW.toString(16));
card.close();
