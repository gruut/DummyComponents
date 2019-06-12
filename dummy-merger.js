var PROTO_PATH = __dirname + '/UserService.proto';

var tools = require('./common-tool.js');
var packer = require('./msg-packer.js');
var authtool = require('./auth-tools.js');
var signtool = require('./agg-gamma-sig.js');

var async = require('async');
var bs58 = require('bs58');
var path = require('path');
var grpc = require('grpc');
const readline = require('readline');
const rl = readline.createInterface({
	input: process.stdin,
	output: process.stdout
});

var protoLoader = require('@grpc/proto-loader');
var packageDefinition = protoLoader.loadSync(PROTO_PATH, {
	keepCase: true,
	longs: String,
	enums: String,
	defaults: true,
	oneofs: true
});
var grpc_user = grpc.loadPackageDefinition(packageDefinition).grpc_user;

var COORD_FACTOR = 1e7;

var MERGER_ID;
var ecKeyPair;
var mergerNonce;
var secretKey;
var height = 0;
var pushService;

function init() {
	ecKeyPair = authtool.generateKeyPair();
	MERGER_ID = bs58.encode(Buffer.from(authtool.getSHA256(ecKeyPair.ecpubhex), 'hex'));
}

var recursiveAsyncReadLine = function(call) {
	rl.question('If you want to send MSG_REQ_SSIG, please enter any key(exit): ', function(answer) {
		if (answer == 'exit') {
			//we need some base case, for recursion
			call.end();
			return rl.close(); //closing RL and returning from function.
		}
		height++;
		var msg = generateMsgReqSsig();
		call.write(msg);
	});
};

function PushService(call) {
	height = 0;
	pushService = call;
	console.log('[READY] PushService');
	recursiveAsyncReadLine(call);
}

function SignerService(call, callback) {
	callback(null, getMessage(call.request));
	recursiveAsyncReadLine(pushService); //Calling this function again to ask new question
}

function keyExService(call, callback) {
	callback(null, getMessage(call.request));
}

function UserService(call, callback) {
	console.log('Not implemented yet.');
}

function getMessage(request) {
	let receivedMsg = packer.unpack(request.message);

	if (receivedMsg.header.msgType == packer.MSG_TYPE.MSG_JOIN) {
		console.log('[RECV] MSG_JOIN');
		return generateMsgChallenge(receivedMsg.body.user);
	} else if (receivedMsg.header.msgType == packer.MSG_TYPE.MSG_RESPONSE_1) {
		console.log('[RECV] MSG_RESPONSE_1');
		return generateMsgResponse2(receivedMsg.body.un, receivedMsg.body.dh);
	} else if (receivedMsg.header.msgType == packer.MSG_TYPE.MSG_SUCCESS) {
		console.log('[RECV] MSG_SUCCESS');
		return generateMsgAccept();
	} else if (receivedMsg.header.msgType == packer.MSG_TYPE.MSG_SSIG) {
		console.log('[RECV] MSG_SSIG');
		return responseToMsgSsig();
	} else {
		console.log('[RECV]' + JSON.stringify(receivedMsg));
		return responseError();
	}
}

function responseToMsgSsig() {
	reply = {
		status: 'SUCCESS',
		message: ''
	};

	console.log('[SEND] MSG_SSIG STATUS');
	return reply;
}

function responseError() {
	reply = {
		status: 'UNKNOWN',
		message: ''
	};

	console.log('[SEND] ERROR');
	return reply;
}

function generateMsgReqSsig() {
	let msg = {};
	msg.block = {};
	msg.producer = {};
	msg.block.time = authtool.getTimestamp();
	msg.block.world = '_TETHYS_';
	msg.block.chain = 'TSTCHAIN';
	msg.block.height = height;
	msg.block.previd = bs58.encode(Buffer.from(authtool.getSHA256(height - 1 + ''), 'hex'));
	msg.block.txroot = authtool.getRandomBase64(32);
	msg.block.usroot = authtool.getRandomBase64(32);
	msg.block.csroot = authtool.getRandomBase64(32);
	msg.producer.id = MERGER_ID;

	msg.block.id = bs58.encode(
		Buffer.from(
			authtool.getSHA256(
				Buffer.concat([
					bs58.decode(msg.producer.id),
					authtool.intToLongBytes(msg.block.time),
					Buffer.from(msg.block.world),
					Buffer.from(msg.block.chain),
					authtool.intToLongBytes(msg.block.height),
					bs58.decode(msg.block.previd)
				])
			),
			'hex'
		)
	);
	msg.producer.sig = authtool.signECDSA(
		ecKeyPair,
		authtool.getSHA256(
			Buffer.concat(
				[
					bs58.decode(msg.block.id),
					Buffer.from(msg.block.txroot, 'base64'),
					Buffer.from(msg.block.usroot, 'base64'),
					Buffer.from(msg.block.csroot, 'base64')
				],
				128
			)
		)
	);

	let msg_pack = packer.pack(packer.MSG_TYPE.MSG_REQ_SSIG, msg, bs58.decode(MERGER_ID));
	var message = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Message', msg_pack);

	console.log('[SEND] MSG_REQ_SSIG');
	return message;
}

function generateMsgChallenge(user_id) {
	mergerNonce = authtool.getRandomBase64(32);

	let msgChallenge = {};
	msgChallenge.time = authtool.getTimestamp();
	msgChallenge.user = user_id;
	msgChallenge.merger = MERGER_ID;
	msgChallenge.mn = mergerNonce;

	let msg_pack = packer.pack(packer.MSG_TYPE.MSG_CHALLENGE, msgChallenge, bs58.decode(MERGER_ID));

	reply = {
		status: 'SUCCESS',
		message: msg_pack
	};

	console.log('[SEND] MSG_CHALLENGE');
	return reply;
}

function generateMsgResponse2(userNonce, userPubPoint) {
	secretKey = authtool.getSecret(ecKeyPair, '04' + userPubPoint.x + userPubPoint.y);

	let point = authtool.getPubPoint(ecKeyPair);
	let msg = {};
	msg.time = authtool.getTimestamp();
	msg.dh = {};
	msg.dh.x = point.x;
	msg.dh.y = point.y;
	msg.merger = {};
	msg.merger.id = MERGER_ID;
	msg.merger.cert = authtool.generateSelfCert(ecKeyPair);

	msg.merger.sig = authtool.signECDSA(
		ecKeyPair,
		Buffer.concat(
			[
				Buffer.from(mergerNonce, 'base64'),
				Buffer.from(userNonce, 'base64'),
				Buffer.from(msg.dh.x, 'hex'),
				Buffer.from(msg.dh.y, 'hex'),
				authtool.intToLongBytes(msg.time)
			],
			136
		)
	);

	let msg_pack = packer.pack(packer.MSG_TYPE.MSG_RESPONSE_2, msg, bs58.decode(MERGER_ID), secretKey);

	reply = {
		status: 'SUCCESS',
		message: msg_pack
	};

	console.log('[SEND] MSG_RESPONSE_2');
	return reply;
}

function generateMsgAccept() {
	let msg = {};
	msg.time = authtool.getTimestamp();
	msg.merger = MERGER_ID;
	msg.val = true;

	let msg_pack = packer.pack(packer.MSG_TYPE.MSG_ACCEPT, msg, bs58.decode(MERGER_ID), secretKey);

	reply = {
		status: 'SUCCESS',
		message: msg_pack
	};

	console.log('[SEND] MSG_ACCEPT');
	return reply;
}

/**
 * Get a new server with the handler functions in this file bound to the methods
 * it serves.
 * @return {Server} The new server object
 */
function getServer() {
	var server = new grpc.Server();
	server.addProtoService(grpc_user.TethysUserService.service, {
		keyExService: keyExService,
		PushService: PushService,
		SignerService: SignerService,
		UserService: UserService
	});
	return server;
}

if (require.main === module) {
	argv = tools.argvParser(process.argv);

	if (!argv.ok) {
		tools.printHowToUse();
		return false;
	}
	var add = 'localhost:' + argv.port;

	init();

	// If this is run as a script, start a server on an unused port
	var mergerServer = getServer();
	mergerServer.bind(add, grpc.ServerCredentials.createInsecure());
	mergerServer.start();
}

exports.getServer = getServer;
