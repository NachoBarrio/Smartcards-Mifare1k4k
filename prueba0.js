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
// variables del terminal
// TLVS

var ahora = new Date();
var tiempo = addZero(ahora.getDate()) + addZero(ahora.getMonth()) + ahora.getFullYear() + addZero(ahora.getHours()) + addZero(ahora.getMinutes());
var HE8 = "E8";
var LE8 = (tiempo.length).toString(16);
if(LE8.length < 2){
	LE8 = "0" + LE8;
}
while (tiempo.length < 14){
	tiempo = tiempo.concat(new ByteString("FF",HEX));
}
var TLVE8 = new ByteString(HE8 + LE8 + tiempo,HEX);

operationNumber = new ByteString("OP-0024514709",ASCII);
TLVE7 = new TLV(0xE7, operationNumber, TLV.EMV);

var d = new Date();
var dateTime = ("0" + d.getDate()).slice(-2) + ("0"+(d.getMonth()+1)).slice(-2) +
    d.getFullYear()+ ("0" + d.getHours()).slice(-2) + ("0" + d.getMinutes()).slice(-2)+ ("0" + d.getSeconds()).slice(-2);
operationTime = new ByteString(dateTime,ASCII);
TLVE8 = new TLV(0xE8, operationTime, TLV.EMV)

merchantCode = new ByteString("M-0024514709",ASCII);
TLVE9 = new TLV(0xE9, merchantCode, TLV.EMV);

transactionId = new ByteString("00",ASCII);
TLVEA = new TLV(0xEA, transactionId, TLV.EMV);

requestType = new ByteString("00",ASCII);
TLVEB = new TLV(0xEB, requestType, TLV.EMV);

verifactionType = new ByteString("00",ASCII);
TLVEC = new TLV(0xEC, verifactionType, TLV.EMV);

amount = new ByteString("50",HEX);
TLVC6 = new TLV(0xC6, amount, TLV.EMV);

// recoger datos de la tarjeta
resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 18 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer nombre 1
var nombre = card.plainApdu(new ByteString("FF B0 00 18 10", HEX));

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 19 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer nombre 2
var nombre2 = card.plainApdu(new ByteString("FF B0 00 19 10", HEX));
nombre = nombre.concat(nombre2);
print("nombre:" +nombre.toString(ASCII));

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1A 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer tarjeta 1
var tarjeta = card.plainApdu(new ByteString("FF B0 00 1A 10", HEX));

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1C 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer tarjeta 2
var tarjeta2 = card.plainApdu(new ByteString("FF B0 00 1C 10", HEX));
tarjeta = tarjeta.concat(tarjeta2);
print("tarjeta:" +tarjeta.toString(ASCII));

resp = card.plainApdu(new ByteString("FF 86 00 00 05 01 00 1D 60 00", HEX));
print("Código SW: " + card.SW.toString(16));
//Leer fecha
var fecha = card.plainApdu(new ByteString("FF B0 00 1D 10", HEX));
print("fecha:" +fecha.toString(ASCII));


//crear tlvs con campos propios de la tarjeta
requestType = new ByteString(tarjeta.toString(ASCII),ASCII);
TLVC1 = new TLV(0xC1, requestType, TLV.EMV);

verifactionType = new ByteString(tarjeta.toString(ASCII),ASCII);
TLVC2 = new TLV(0xC2, verifactionType, TLV.EMV);

amount = new ByteString(fecha.toString(ASCII),ASCII);
TLVC3 = new TLV(0xC3, amount, TLV.EMV);

//concatenar unidad de gasto
TLVListExpenseUnit = new TLVList(TLVC6.getTLV(),TLV.EMV);
TLVListExpenseUnit.append(TLVE8.getTLV());
TLVListExpenseUnit.append(TLVE7.getTLV());
TLVListExpenseUnit.append(TLVEA.getTLV());
TLVListExpenseUnit.append(TLVE9.getTLV());
TLVListExpenseUnit.append(TLVC2.getTLV());
TLVListExpenseUnit.append(TLVC3.getTLV());
TLVListExpenseUnit.append(TLVC1.getTLV());
TLVListExpenseUnit.append(TLVEB.getTLV());
TLVListExpenseUnit.append(TLVEC.getTLV());
expenseUnit =TLVListExpenseUnit.toByteString();
print("Lista gasto:" + TLVListExpenseUnit.toByteString());
enc = encryptAES_CBC(expenseUnit,KT, iv);
MAC = enc[0].right(8).left(4);
expenseUnit = expenseUnit.concat(MAC);
encExpenseUnit = encryptAES_CBC(expenseUnit,KM, iv);
enc2 = encryptAES_CBC(encExpenseUnit[0],KT, iv);
MAC2 = enc2[0].right(8).left(4);

effectiveExpenseUnit = encExpenseUnit[0].concat(MAC2);

var fichero = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastoenviada.txt";
file = new java.io.File(filename);
if (!file.exists()){
  file.createNewFile();
 }


fw = new java.io.FileWriter (file.getAbsoluteFile());
bw = new java.io.BufferedWriter(fw);

bw.write(effectiveExpenseUnit.toString(BASE64));
bw.close();
print();
print("Unidad de gasto enviada correctamente en: "+file.getAbsoluteFile()); 

card.close();