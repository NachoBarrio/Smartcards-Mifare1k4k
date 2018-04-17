card = new Card();
atr = card.reset(Card.RESET_COLD);

//constantes crifrado
var crypto = new Crypto();
var deskey = new Key();

var Kt = new ByteString("CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB", HEX);
var Km = new ByteString("88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77", HEX);

var VI = new ByteString("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", HEX);

deskey.setComponent(Key.AES, Kt);

function addZero(i) {
    if (i < 10) {
        i = "0" + i;
    }
    return i;
}

function relleno(rellenar){
	while((16 - (rellenar.length % 16)) % 16 > 0){
		rellenar = rellenar.concat(new ByteString("00",HEX));
	}
	return rellenar;
}
//Carga la clave en el lector. ff ff ff ff ff ff en la posicion 0.
resp = card.plainApdu(new ByteString("FF 82 20 00 06 FF FF FF FF FF FF", HEX));
print(card.SW.toString(16));
//
//Lee el serial number de la tarjeta
resp = card.plainApdu(new ByteString("FF CA 00 00 04", HEX));
print("SERIAL NUMBER: " + resp);
print(card.SW.toString(16));
print();

var fichero = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastorecibida.txt";
file = new java.io.File(fichero);
if (!file.exists()){
 print("File not found");
}else{
	fr = new java.io.FileReader (file.getAbsoluteFile());
	br = new java.io.BufferedReader(fr);
	if(linea = br.readLine()){
		var uCifradoLinea = new ByteString(linea,BASE64);
		MACU2 = uCifradoLinea.right(4);
		var uCifrado2 = uCifradoLinea.bytes(0,uCifradoLinea.length-4);
		
		//segundo cifrado
		var uCifrado2 = relleno(uCifrado2);
		var uCifrado = crypto.encrypt(deskey, Crypto.AES_CBC, uCifrado2, VI);
		var MACu2 = uCifrado.right(8).left(4);
		print("comparar mac 2: "+MACu2+"<---->"+MACU2);
		
		if(MACu2.toString() != MACU2.toString()){
			print("Error");
		}else{
		deskey.setComponent(Key.AES, Km);
		  var uDescifrado2 =  crypto.decrypt(deskey,Crypto.AES_CBC, uCifrado2,VI)
		  //busqueda por HEX referente al TLV que nos interesa (solo datos)
		  var MACU1 = uDescifrado2.bytes(uDescifrado2.find(new ByteString("EC",HEX))+4,4);
		  
	      uDescifrado2 = uDescifrado2.bytes(0,uDescifrado2.find(new ByteString("EC",HEX))+4);
	      ListaUGasto = new TLVList(uDescifrado2,TLV.EMV);
		  //primer cifrado
		   deskey.setComponent(Key.AES, Kt);
		   var uConcatRelleno2 = relleno(ListaUGasto.toByteString());
		   var uCifrado = crypto.encrypt(deskey, Crypto.AES_CBC, uConcatRelleno2, VI);
		   var MACu1 = uCifrado.right(8).left(4);
		   print("comparar mac 1: "+MACu1+"<---->"+MACU1); 
		   if(MACu2.toString() != MACU2.toString()){
			print("Error");
		   }else{
		   	//si todas las comprobaciones correctas ///TODO Copiar Verifica.js
		   	TLVcodPet =  ListaUGasto.find(0xEB);
		   	print("La petición realizada ha sido: "+TLVcodPet.getValue().toString(ASCII));
		   }		   	
		}
	}
	
}