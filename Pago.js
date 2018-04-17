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
// TLVS del plugin para ahorrar calculo de longitudes en tantas tlvs distintas, no pude hacerlo funcionar con forma antigua ante tantos calculos distintos
// se mantiene la estructura anterior para las que se alamacenaron en la tarjeta

var ahora = new Date();
var tiempo = addZero(ahora.getDate()) + addZero(ahora.getMonth()) + ahora.getFullYear() + addZero(ahora.getHours()) + addZero(ahora.getMinutes());

var tiempo = new ByteString(tiempo,ASCII);
var TLVE8 = new TLV(0xE8, tiempo, TLV.EMV)
var numOp = new ByteString("CAS000001111",ASCII);
var TLVE7 = new TLV(0xE7, numOp, TLV.EMV);
var codEst = new ByteString("EST00010",ASCII);
var TLVE9 = new TLV(0xE9, codEst, TLV.EMV);
var codTrans = new ByteString("00",ASCII);
var TLVEA = new TLV(0xEA, codTrans, TLV.EMV);
var codPet = new ByteString("01",ASCII);
var TLVEB = new TLV(0xEB, codPet, TLV.EMV);
var codVer = new ByteString("00",ASCII);
var TLVEC = new TLV(0xEC, codVer, TLV.EMV);
//carga de 30 e
var carga = new ByteString("30",HEX);
var TLVC6 = new TLV(0xC6, carga, TLV.EMV);

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
var nombreTLV = new ByteString(nombre.toString(ASCII),ASCII);
var TLVC1 = new TLV(0xC1, nombreTLV, TLV.EMV);
var tarjetaTLV = new ByteString(tarjeta.toString(ASCII),ASCII);
var TLVC2 = new TLV(0xC2, tarjetaTLV, TLV.EMV);
var fechaTLV = new ByteString(fecha.toString(ASCII),ASCII);
var TLVC3 = new TLV(0xC3, fechaTLV, TLV.EMV);

//concatenar unidad de gasto
ListaUGasto = new TLVList(TLVC6.getTLV(),TLV.EMV);
ListaUGasto.append(TLVE8.getTLV());
ListaUGasto.append(TLVE7.getTLV());
ListaUGasto.append(TLVEA.getTLV());
ListaUGasto.append(TLVE9.getTLV());
ListaUGasto.append(TLVC2.getTLV());
ListaUGasto.append(TLVC3.getTLV());
ListaUGasto.append(TLVC1.getTLV());
ListaUGasto.append(TLVEB.getTLV());
ListaUGasto.append(TLVEC.getTLV());
print("Lista gasto:" + ListaUGasto.toByteString());
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

var fichero = "/Users/ignaciobarriosantos/eclipse-workspace/Mifare1K4K/ugastoenviada.txt";
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