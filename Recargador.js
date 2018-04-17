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

// inicio recargador
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
var dinero = descifrado.bytes(1,4);
var valorMaximo = descifrado.bytes(5,2);
var numViajesEscritos = resp.bytes(8,1);
print("Valor actual del monedero: "+dinero.toSigned());
print("Valor max del monedero: "+valorMaximo.toSigned());

// Sumar valor al monedero ej 2e = 200cents
var recarga = 200;
if( (dinero.toSigned() + recarga) > valorMaximo.toSigned()){
	print("No se puede realizar la operación al limitar el maximo");
}else{
	nuevoMonedero =  dinero.toSigned() + recarga;
	//Convertir decimal a hexadecimal
	var monToHex = nuevoMonedero.toString(16);
	while(monToHex.toString().length < 4){
		monToHex =  "0" + monToHex;
	}
	
	var nMonedero = new ByteString(monToHex,HEX);
	
	print("nueva suma: "+nuevoMonedero.toString());
	while(nMonedero.length < 4){
		nMonedero =  new ByteString("00", HEX).concat(nMonedero);
	}
	var monederoConcat = new ByteString(descifrado.bytes(0,1)+nMonedero+descifrado.bytes(5,3), HEX);
	
	
	var monederoConcatCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, monederoConcat, VI);
	//SE AUTENTICA CON EL BLOQUE 9 del SECTOR 2
	//
	resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 09 60 00", HEX));
	print("Código SW: " + card.SW.toString(16));
	
	//Escribe los datos personales en el sector 2 bloque 9 rellenando el bloque
	resp = card.plainApdu(new ByteString("FF D6 00 09 10", HEX).concat(monederoConcatCifrado).concat(numViajesEscritos).concat(completar.bytes(0,7)));
	print("Código SW: " + card.SW.toString(16));
}
card.close();
