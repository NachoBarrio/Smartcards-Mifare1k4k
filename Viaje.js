card = new Card();
atr = card.reset(Card.RESET_COLD);
var completar = new ByteString("FF FF FF FF FF FF FF FF",HEX);
var completarSector = new ByteString("FF FF FF FF",HEX);
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
//Funciones para uso con fechas
function addZero(i) {
    if (i < 10) {
        i = "0" + i;
    }
    return i;
}




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
print("Valor actual del monedero: "+dinero.toSigned());

//Comprobar y registrar viaje
// Array con sectores donde se guardarán los registros
var bloquesRegistro = ["0C","0D","0E","10","11","12","13","14"];
var costeViaje = 80;
if( (dinero.toSigned() - costeViaje) < 0){
	print("No hay saldo disponible para viajar");
}else{
	nuevoMonedero =  dinero.toSigned() - costeViaje;
	print("nuevo saldo: "+nuevoMonedero.toString());
	
	var numViajesEscritos = resp.bytes(8,1).toSigned();
	print("número de viajes escritos: "+numViajesEscritos);
	if(numViajesEscritos == 8){
	 numViajesEscritos = 1;
	}else{
	 numViajesEscritos++;
	}
	var contViajesEscritos = new ByteString("0"+numViajesEscritos,HEX);
	print("numViajesEscritos :"+contViajesEscritos);
	
	
	//Actualizar monedero
	//Convertir decimal a hexadecimal
	var monToHex = nuevoMonedero.toString(16);
	while(monToHex.toString().length < 4){
		monToHex =  "0" + monToHex;
	}
	var nMonedero = new ByteString(monToHex,HEX);
	while(nMonedero.length < 4){
		nMonedero =  new ByteString("00", HEX).concat(nMonedero);
	}
	
	var monederoConcat = new ByteString(descifrado.bytes(0,1) + nMonedero + descifrado.bytes(5,3),HEX);
	print("todo: "+monederoConcat);
	
	var monederoConcatCifrado = crypto.encrypt(deskey, Crypto.DES_CBC, monederoConcat, VI);
	//SE AUTENTICA CON EL BLOQUE 9 del SECTOR 2
	//
	resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 09 60 00", HEX));
	print("Código SW: " + card.SW.toString(16));
	//Escribe los datos personales en el sector 2 bloque 9 rellenando el bloque
	resp = card.plainApdu(new ByteString("FF D6 00 09 10", HEX).concat(monederoConcatCifrado).concat(contViajesEscritos).concat(completar.bytes(0,7)));
	print("Código SW: " + card.SW.toString(16));
	
	
	//Escribe el registro del viaje en su sector correspondiente
	var sector = bloquesRegistro[numViajesEscritos-1];
	//SE AUTENTICA CON EL BLOQUE X del SECTOR Y
	//
	print("sector a pintar: "+sector);
	resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00"+ sector +"60 00", HEX));
	print("Código SW: " + card.SW.toString(16));
	
    var ahora = new Date();
    print("date:"+ahora);
	var codFechaDia = addZero(ahora.getDate());
	var codFechaMes = addZero(ahora.getMonth());
	var codFechaAnio = ahora.getFullYear();
	var codHora = addZero(ahora.getHours());
	var codMin = addZero(ahora.getMinutes());
	var codLinea = "00 01";
	var codParada = "00 01";
	var codBus = "C0 02";
	
	var registroConcat = new ByteString(codFechaDia+codFechaMes+codFechaAnio+codHora+codMin+codLinea+codParada+codBus,HEX);
	
	resp = card.plainApdu(new ByteString("FF D6 00"+ sector +"10", HEX).concat(registroConcat).concat(completarSector));
	print("Código SW: " + card.SW.toString(16));
}
card.close();