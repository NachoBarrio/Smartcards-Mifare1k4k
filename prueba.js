
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

var BALANCE = 5000;
KT = new ByteString("CC DD EE FF 00 11 22 33 44 55 66 77 88 99 AA BB",HEX);
KM = new ByteString("88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77",HEX);
iv = ByteString.valueOf(0,16);
var filename = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastoenviada.txt";

//Escribir en fichero
file = new java.io.File(filename);
if (!file.exists()){
 print("No existe ningun fichero de gasto");
}else{

	fr = new java.io.FileReader (file.getAbsoluteFile());
	br = new java.io.BufferedReader(fr);
	if( base64 = br.readLine()){
      br.close();
	  effectiveExpenseUnit = new ByteString (base64, BASE64);
	  MAC2 = effectiveExpenseUnit.right(4);
	  encExpenseUnit=effectiveExpenseUnit.left(effectiveExpenseUnit.length-4);
	  enc2 = encryptAES_CBC(encExpenseUnit,KT, iv);
	  calculatedMac2 = enc2[0].right(8).left(4);
	  print("comparar mac 1: "+MAC2+"<---->"+calculatedMac2);
	  if(calculatedMac2.equals(MAC2)){
	  
	   expenseUnit = decryptAES_CBC(encExpenseUnit,KM,iv);
	   MAC1 = expenseUnit.bytes(expenseUnit.find(new ByteString("EC",HEX))+4,4);
	   expenseUnit = expenseUnit.bytes(0,expenseUnit.find(new ByteString("EC",HEX))+4);
	   TLVsExpenseUnit = new TLVList(expenseUnit,TLV.EMV);
	   enc = encryptAES_CBC(TLVsExpenseUnit.toByteString(),KT, iv);
	   calculatedMac1 = enc[0].right(8).left(4);
	    print("comparar mac 2: "+MAC1+"<---->"+calculatedMac1);
	   if(calculatedMac1.equals(MAC1)){
	     var d = new Date();
	     monthYear = ("0"+(d.getMonth()+1)).slice(-2) +(""+d.getFullYear()).slice(-2);

	     TLVC3 =TLVsExpenseUnit.find(0xC3);
	     expirationDate =TLVC3.getValue(ASCII);
	     if(expirationDate > monthYear){
	        TLVEA =TLVsExpenseUnit.find(0xEA);
	        transactionId = TLVEA.getValue().toString(ASCII);
	        TLVC6 =TLVsExpenseUnit.find(0xC6);
	        amount = TLVC6.getValue().toString(16);
	        print("amount:"+amount);
	        switch(transactionId){
		        case "00":
		        	   if(BALANCE >= amount){
		        	    BALANCE = BALANCE -amount;
		                TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
		               }else{
		                 TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV);
		               }
		             break;
		        case "01":
		        	   BALANCE = BALANCE +amount; 
		               TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
		              break;
		        case "02":
		        	  if(BALANCE >= amount){
		        	    BALANCE = BALANCE -amount;
		                 TLVEB = new TLV(0xEB, new ByteString("01",ASCII), TLV.EMV);
		               }else{
		                 TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV);
		               }
		             break;
		        default:
		            TLVEB = new TLV(0xEB, new ByteString("03",ASCII), TLV.EMV);   
	        }
	        
	     }else{
	         TLVEB = new TLV(0xEB, new ByteString("02",ASCII), TLV.EMV);
	     }
	   }else{
	     TLVEB = new TLV(0xEB, new ByteString("03",ASCII), TLV.EMV);   
	  	}
	  }else{
	    TLVEB = new TLV(0xEB, new ByteString("03",ASCII), TLV.EMV);   
	  }
	  
	  TLVsExpenseUnit.updateValue(0xEB, TLVEB.getValue());
      expenseUnit =TLVsExpenseUnit.toByteString();
	  enc = encryptAES_CBC(expenseUnit,KT, iv);
      MAC = enc[0].right(8).left(4);
  

      expenseUnit = expenseUnit.concat(MAC);
      encExpenseUnit = encryptAES_CBC(expenseUnit,KM, iv);
      enc2 = encryptAES_CBC(encExpenseUnit[0],KT, iv);
      MAC2 = enc2[0].right(8).left(4);
      effectiveExpenseUnit = encExpenseUnit[0].concat(MAC2);
	  
      var filename = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastorecibida.txt";

      file = new java.io.File(filename);
      if (!file.exists()){
         file.createNewFile();
      }

	  fw = new java.io.FileWriter (file.getAbsoluteFile());
	  bw = new java.io.BufferedWriter(fw);
	
	  bw.write(effectiveExpenseUnit.toString(BASE64));
	  bw.close();
	  print();
	  print("Unidad de gasto recibida correctamente en: "+file.getAbsoluteFile());
	}else{
	  print("Error: Fichero de gasto vacio");  
	}

}
