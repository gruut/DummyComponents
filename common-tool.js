var validator = require('validator');

const argvParser = function(process_argv) {
	var obj = {};
	const len = process_argv.length;
	switch (len) {
		case 5:
			obj.n = process_argv[4];

		case 4:
			obj.n = obj.n ? obj.n : 1;
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

const checkArgs = function(obj) {
	try {
		if (!validator.isNumeric(obj.n.toString())) {
			obj.n = null;
			obj.ok = false;
		}
		if (!(validator.isIP(obj.addr) || validator.isURL(obj.addr) || obj.addr.toLowerCase() == 'localhost')) {
			obj.addr = null;
			obj.ok = false;
		}
		if (!validator.isPort(obj.port)) {
			obj.port = null;
			obj.ok = false;
		}
	} catch (err) {
		console.log(err);
		obj.ok = false;
	}
};

const printHowToUse = function() {
	console.log('Error: Invalid arguments. Please follow the instructions below.');
	console.log('node [script_name] [ip_or_addr] [port] [emulator_id]');
	console.log('- [script_name] should be one of these [merger, signer, tx_generator]');
	console.log('- [ip_or_addr] should be a valid form of IP or URL ');
	console.log('- [port] should be a number less than 65535');
	console.log('- [se_id] should be a number (default: 1)');
};

var self = (module.exports = {
	argvParser: argvParser,
	printHowToUse: printHowToUse
});
