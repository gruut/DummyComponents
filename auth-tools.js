const cryptoUtils = require('jsrsasign');
const crypto = require('crypto');
const secureRandom = require('secure-random');

const getTimestamp = function() {
	return Math.floor(Date.now() / 1000).toString();
};

const getSHA256 = function(data) {
	return crypto.createHash('sha256').update(data).digest('hex');
};

const getRandomBase64 = function(length) {
	var r = secureRandom(length, { type: 'Buffer' });
	return Buffer.from(r).toString('base64');
};

// convert INTEGER into 4 bytes array
const intToLongBytes = function(int) {
	let buf = Buffer.allocUnsafe(4);
	buf.writeInt32BE(int, 0);
	return buf;
};

const generateKeyPair = function() {
	var ec = new cryptoUtils.crypto.ECDSA({ curve: 'secp256k1' });
	return ec.generateKeyPairHex();
};

const generateSelfCert = function(keyPair) {
	var ec = new cryptoUtils.crypto.ECDSA({ curve: 'secp256k1' });
	ec.setPrivateKeyHex(keyPair.ecprvhex);
	ec.setPublicKeyHex(keyPair.ecpubhex);

	var tbsc = new cryptoUtils.asn1.x509.TBSCertificate();
	tbsc.setSerialNumberByParam({ int: 1 });
	tbsc.setSignatureAlgByParam({ name: 'SHA256withECDSA' });
	tbsc.setIssuerByParam({
		str: '/C=DE/O=dummy-issuer/CN=CA'
	});
	tbsc.setNotBeforeByParam({ str: '20140924120000Z' });
	tbsc.setNotAfterByParam({ str: '20300101000000Z' });
	tbsc.setSubjectByParam({ str: '/C=DE/O=dummy-subject/CN=dummy' });

	tbsc.setSubjectPublicKeyByGetKey(ec);

	const cert = new cryptoUtils.asn1.x509.Certificate({
		tbscertobj: tbsc,
		prvkeyobj: ec
	});
	cert.sign();

	return cert.getPEMString();
};

const signECDSA = function(keyPair, data) {
	var ec = new cryptoUtils.crypto.ECDSA({ curve: 'secp256k1' });
	ec.setPrivateKeyHex(keyPair.ecprvhex);
	ec.setPublicKeyHex(keyPair.ecpubhex);

	var sigValue = ec.signHex(data.getSHA256, keyPair.ecprvhex);
	return Buffer.from(sigValue, 'hex').toString('base64'); //BASE64
};

const getPubPoint = function(keyPair) {
	var ec = new cryptoUtils.crypto.ECDSA({ curve: 'secp256k1', pub: keyPair.ecpubhex });
	return ec.getPublicKeyXYHex();
};

const getSecret = function(keyPair, otherPubKey) {
	var ecdh = crypto.createECDH('prime256v1');
	ecdh.setPrivateKey(keyPair.ecprvhex, 'hex');

	return ecdh.computeSecret(otherPubKey, 'hex');
};

const self = (module.exports = {
	getTimestamp: getTimestamp,
	getSHA256: getSHA256,
	getRandomBase64: getRandomBase64,
	intToLongBytes: intToLongBytes,
	generateKeyPair: generateKeyPair,
	generateSelfCert: generateSelfCert,
	signECDSA: signECDSA,
	getPubPoint: getPubPoint,
	getSecret: getSecret
});
