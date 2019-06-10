/**
 * Implements Utility Functions
 */

var winston = require('winston');
require('date-utils');
const fs = require('fs');
var crypto = require('crypto');
var validator = require('validator');
var secureRandom = require('secure-random');
const cryptoUtils = require('jsrsasign');

const privateKeyHex = "e01315851b27e9878fb49545417dfb807998e672d9b37f4e262adb9c37ff68c9";
const publicKeyHex = "04c23850deb891147d12d78179b0a2fcc4257dd08f46856a5da4d5eeef996ec6499fe3036ef96ce5880194e2c671d3ddaffd781ddfa265f87cbd7b96f0b60d94ae"

// https://stackoverflow.com/questions/32131287/how-do-i-change-my-node-winston-json-output-to-be-single-line
var getLogger = function(type_name){
	const logDir = 'logs';
	if (!fs.existsSync(logDir)) {
		fs.mkdirSync(logDir);
	}

	const { splat, combine, timestamp, printf } = winston.format;

	// meta param is ensured by splat()
	const myFormat = printf(({ timestamp, level, message, meta }) => {
	return `${timestamp};${level};${message};${meta? JSON.stringify(meta) : ''}`;
	});

	var options = {
		file: {
			level: 'info',
			name: 'server.info',
			filename: 'logs/' + type_name + '.log',
			handleExceptions: true,
			maxsize: 5242880, // 5MB
			maxFiles: 100,
		},
		errorFile: {
			level: 'error',
			name: 'server.error',
			filename: 'logs/' + type_name + 'error.log',
			handleExceptions: true,
			maxsize: 5242880, // 5MB
			maxFiles: 100,
		},
		console: {
			level: 'debug',
			handleExceptions: true,
		}
	};

	return winston.createLogger({
		format: combine(
			timestamp(),
			splat(),
			myFormat
		),
		transports: [
			new (winston.transports.File)(options.errorFile),
			new (winston.transports.File)(options.file),
			new (winston.transports.Console)(options.console)
		],
		exitOnError: false, // do not exit on handled exceptions
	});
};

var getHMAC = function(data){
	const secret = '0x0000000000000000000000000000000000000000000000000000000000000000';
	const hash = crypto.createHmac('sha256', Buffer.from(secret, 'hex'))
	                   .update(data)
	                   .digest('hex');
	return hash;
}

var getSHA256 = function(data){
	return crypto.createHash('sha256').update(data).digest('hex');
};

var getRandomBase64 = function(length){
    var r = secureRandom(length, {type: 'Buffer'});
    return Buffer.from(r).toString('base64');
}

// check out this https://nodejs.org/api/crypto.html#crypto_class_sign
const signRSA = function(data){
	var signer = crypto.createSign('sha256');
	signer.update(data);
	return signer.sign(privateKey,'base64');
};

const signECDSA = function(hash) {
	var ec = new cryptoUtils.crypto.ECDSA({'curve': 'secp256r1'});
	var sigValue = ec.signHex(hash, privateKeyHex);

  return Buffer.from(sigValue, 'hex').toString('base64') //BASE64
}

const getTimestamp = function(){
	return (Math.floor(Date.now() / 1000)).toString();
};

const argvParser = function(process_argv){
    var obj = {};
	const len = process_argv.length;
    switch (len){
		case 5:
		obj.n = process_argv[4];

		case 4:
		obj.n = (obj.n)? obj.n : 1;
        obj.addr = process_argv[2];
		obj.port = process_argv[3];
		obj.ok = true;
		checkArgs(obj);
        break;

        default:
        obj.ok = false;
        break;
	}
	return obj;
};

const checkArgs = function(obj){
	try{
		if( !validator.isNumeric(obj.n.toString())){
			obj.n = null;
			obj.ok = false;
		}
		if( !(validator.isIP(obj.addr) || validator.isURL(obj.addr) || obj.addr.toLowerCase() == "localhost") ){
			obj.addr = null;
			obj.ok = false;
		}
		if( !validator.isPort(obj.port)){
			obj.port = null;
			obj.ok = false;
		}
	}
	catch (err){
		console.log(err);
		obj.ok = false;
	}
};

const printHowToUse = function(){
	console.log ("Error: Invalid arguments. Please follow the instructions below.");
	console.log ("node [script_name] [ip_or_addr] [port] [emulator_id]");
	console.log ("- [script_name] should be one of these [merger, signer, tx_generator]");
	console.log ("- [ip_or_addr] should be a valid form of IP or URL ");
	console.log ("- [port] should be a number less than 65535");
	console.log ("- [se_id] should be a number (default: 1)");
};

const getECDSAKeyPair = function() {
	var ecdsa = new cryptoUtils.crypto.ECDSA({'curve': 'secp256r1'});
	
	ecdsa.setPrivateKeyHex(privateKeyHex);
	ecdsa.setPublicKeyHex(publicKeyHex);
	
	return ecdsa
}

const createCert = function(ecdsa) {
		var tbsc = new cryptoUtils.asn1.x509.TBSCertificate();
	tbsc.setSerialNumberByParam({"int": 1});
	tbsc.setSignatureAlgByParam({'name': "SHA256withECDSA"});
	tbsc.setIssuerByParam({
			"str": "/C=DE/O=dummy-issuer/CN=CA"
	});
	tbsc.setNotBeforeByParam({'str': "20140924120000Z"});
	tbsc.setNotAfterByParam({'str': "20300101000000Z"});
	tbsc.setSubjectByParam({'str': "/C=DE/O=dummy-subject/CN=dummy"});

	tbsc.setSubjectPublicKeyByGetKey(ecdsa);

	const cert = new cryptoUtils.asn1.x509.Certificate({
		tbscertobj: tbsc,
		prvkeyobj: ecdsa,
	});
	cert.sign();

	return cert.getPEMString();
}

var self = module.exports = {
	getLogger : getLogger,
	getHMAC : getHMAC,
	getSHA256 : getSHA256,
  signRSA : signRSA,
  signECDSA : signECDSA,
	getTimestamp : getTimestamp,
	argvParser : argvParser,
	printHowToUse: printHowToUse,
	getRandomBase64 : getRandomBase64,
	getECDSAKeyPair: getECDSAKeyPair,
  createCert : createCert
};