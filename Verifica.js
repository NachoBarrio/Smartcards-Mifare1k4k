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

//variables locales
//Monedero 100e
var monedero = 100;


//Leer fichero
var fichero = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastoenviada.txt";
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
			TLVEB = new TLV(0xEB, new ByteString("03",ASCII), TLV.EMV); 
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
			TLVEB = new TLV(0xEB, new ByteString("03",ASCII), TLV.EMV); 
		   }else{
		   //fecha de prueba por falta de tiempo
		     var ahora= new Date();
		     concAhora = ("0"+(ahora.getMonth()+1)).slice(-2) +(""+ahora.getFullYear()).slice(-2);
	
		     TLVfecha =ListaUGasto.find(0xC3);
		     fecha =TLVfecha.getValue(ASCII);
		     if(fecha < concAhora){
		    	print("caducada");
		    	TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV); 
		     }else{
		     	TLVgasto = ListaUGasto.find(0xC6);
		    	gasto = TLVgasto.getValue().toString(16);		    
	        	print("gasto:"+gasto);
	        	//tipo de transaccion
	        	TLVcodTran = ListaUGasto.find(0xEA);
	        	codTran = TLVcodTran.getValue().toString(ASCII);
	        	if(codTran = "00"){
	        	  monedero = monedero - gasto;
	        	  monedero < 0 ? TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV) : TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
	        	  print("venta");
	        	 }else if(codTran = "01"){
	        	  monedero = monedero + gasto;
	        	  TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
	        	  print("devolucion");
	        	 }else if(codTran = "02"){
	        	  monedero < 0 ? TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV) : TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
	        	  print("reservado");
	        	 }
	     	}
	     	
		   }	   
		 print("escribir de vuelta en fichero de salida");
		 //actualizar codigo de peticion con resultado operacion
		 ListaUGasto.updateValue(0xEB, TLVEB.getValue());
		 //Calculo de las MACs  
		 var uGasto =ListaUGasto.toByteString();
		
		 var uGastoRelleno = relleno(uGasto);
		 var uGastoCifrado = crypto.encrypt(deskey, Crypto.AES_CBC, uGastoRelleno, VI);
		 var MAC1 = uGastoCifrado.right(8).left(4);
		 //concatenar primera mac
         uGasto = uGasto.concat(MAC1);
         deskey.setComponent(Key.AES, Km);
		 var uGastoRelleno = relleno(uGasto);
		 var uGastoCifrado = crypto.encrypt(deskey, Crypto.AES_CBC, uGastoRelleno, VI);
		 deskey.setComponent(Key.AES, Kt);
		 var uGastoRelleno2 = relleno(uGastoCifrado);
		 var uGastoCifrado2 = crypto.encrypt(deskey, Crypto.AES_CBC, uGastoRelleno2, VI);
		 var MAC2 = uGastoCifrado2.right(8).left(4);

		 //concatenar segunda mac
		 var resulTot = uGastoCifrado.concat(MAC2);
		
		 var fichero = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastorecibida.txt";
		 file = new java.io.File(fichero);
		 if (!file.exists()){
		   file.createNewFile();
		  }
		 fw = new java.io.FileWriter (file.getAbsoluteFile());
		 bw = new java.io.BufferedWriter(fw);
		 bw.write(resulTot.toString(BASE64));
		 bw.close();
		 print("Unidad de gasto enviada, fichero: "+file.getAbsoluteFile()); 
		 card.close();
			 }
		 }
	
	 }