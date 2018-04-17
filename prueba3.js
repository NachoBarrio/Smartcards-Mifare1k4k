function encryptAES_CBC(data,key,iv){
 nb = data.length;
 padding="";
 if((nb % 16)){
   next_multiple = nb + (16 - nb % 16);
   padding=new ByteString.valueOf(0, next_multiple -nb);
   data=data.concat(padding);
 }
 var crypto= new Crypto();
 var key = new ByteString(key, HEX);
 var aeskey = new Key();
 iv = new ByteString(iv,HEX);
 aeskey.setComponent(Key.AES, key);
 return new Array(crypto.encrypt(aeskey, Crypto.AES_CBC, data,iv), padding.length);
}

function decryptAES_CBC(data,key,iv){
 var crypto= new Crypto();
 var key = new ByteString(key, HEX);
 var aeskey = new Key();
 iv = new ByteString(iv,HEX);
 aeskey.setComponent(Key.AES, key);
 return crypto.decrypt(aeskey, Crypto.AES_CBC, data,iv);
}


KT = new ByteString("CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB",HEX);
KM = new ByteString("88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77",HEX);
iv = ByteString.valueOf(0,16);
var filename = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastorecibida.txt";

//Escribir en fichero
file = new java.io.File(filename);
if (!file.exists()){
 print("No existe ningun fichero de gasto recibida");
}else{

	fr = new java.io.FileReader (file.getAbsoluteFile());
	br = new java.io.BufferedReader(fr);
	if( base64 = br.readLine()){
	  effectiveExpenseUnit = new ByteString (base64, BASE64);
	  MAC2 = effectiveExpenseUnit.right(4);
	  encExpenseUnit=effectiveExpenseUnit.left(effectiveExpenseUnit.length-4);
	  enc2 = encryptAES_CBC(encExpenseUnit,KT, iv);
	  calculatedMac2 = enc2[0].right(8).left(4);
	  if(calculatedMac2.equals(MAC2)){
	     expenseUnit = decryptAES_CBC(encExpenseUnit,KM,iv);
	     MAC1 = expenseUnit.bytes(expenseUnit.find(new ByteString("EC",HEX))+4,4);
	     expenseUnit = expenseUnit.bytes(0,expenseUnit.find(new ByteString("EC",HEX))+4);
	  
	     TLVsExpenseUnit = new TLVList(expenseUnit,TLV.EMV);
	     enc = encryptAES_CBC(expenseUnit,KT, iv);
	     calculatedMac1 = enc[0].right(8).left(4);
	     if(calculatedMac1.equals(MAC1)){
	         TLVEB =TLVsExpenseUnit.find(0xEB);
	         print();
	         print("Tipo de petición: "+TLVEB.getValue().toString(ASCII));
	         print("Pago verificado correctamente");
	     }
	   }
	}else{
	  print("Error: Fichero de gasto vacio");  
	}

}
