var validator = require('validator');

const argvParser = function(process_argv) {
	var obj = {};
	const len = process_argv.length;
	switch (len) {
		case 4:
			obj.addr = process_argv[2];
			obj.port = process_argv[3];
			obj.ok = true;
			checkArgs(obj);
			break;
		case 3:
			obj.addr = 'localhost';
			obj.port = process_argv[2];
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
	console.log('npm run merger [port]');
	console.log('- enter the port number to open as a merger');
	console.log('- [port] should be a number less than 65535');
	console.log('');
	console.log('npm run signer [ip_or_addr] [port]');
	console.log('- enter merger`s address and port number to connect');
	console.log('- [ip_or_addr] should be a valid form of IP or URL');
	console.log('- [port] should be a number less than 65535');
};

var self = (module.exports = {
	argvParser: argvParser,
	printHowToUse: printHowToUse
});
