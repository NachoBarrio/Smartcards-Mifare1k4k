/* LEE TODOS LOS SECTORES DE MIFARE EN CONDICIONES DE TRANSPORTE*/
/* SE SUPONE QUE LA KEYA ES FFFFFFFFFFFF PARA TODOS LOS SECTORES */
/* ESTE SCRIPT ES PARA EL LECTOR ACR128 */

card = new Card();
atr = card.reset(Card.RESET_COLD);
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

for (var j = 0; j < 16; j++) {
	a = new ByteString("FF860000050100", HEX);
	f = new ByteString("6000", HEX);
	m = ByteString.valueOf(j*4);
	//SE FORMA LA APDU PARA AUTENTICARSE CON CADA SECTOR
	KEYapdu = a.concat(m.concat(f));
	//SE REALIZA LA AUTENTICACIÓN CON CADA SECTOR
	resp = card.plainApdu(KEYapdu);
	print("SECTOR " + ByteString.valueOf(j, 1)+ ":");
	
		for (var i = 0; i < 4; i++) {
					resp = card.sendApdu(0xFF, 0xB0, 0x00, (i+(j*4)), 0x10);
					print("BLOQUE " + ByteString.valueOf((i+(j*4)), 1) + ": "+  resp + "   " + resp.toString(ASCII));
					}
		print();
}
card.close();