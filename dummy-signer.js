var PROTO_PATH = __dirname + '/UserService.proto';
var AUTH_URL = 'http://ec2-13-209-161-44.ap-northeast-2.compute.amazonaws.com:48080/v1/users';

var tools = require('./common-tool.js');
var packer = require('./msg-packer.js');
var authtool = require('./auth-tools.js');
var signtool = require('./agg-gamma-sig.js');

var async = require('async');
var bs58 = require('bs58');
var path = require('path');
var grpc = require('grpc');
var request = require('request');
var protoLoader = require('@grpc/proto-loader');
var packageDefinition = protoLoader.loadSync(PROTO_PATH, {
	keepCase: true,
	longs: String,
	enums: String,
	defaults: true,
	oneofs: true
});
var grpc_user = grpc.loadPackageDefinition(packageDefinition).grpc_user;
var stub;

var COORD_FACTOR = 1e7;

var ecKeyPair;
var certificate;
var userId;
var userNonce;
var secretKey;

function init(callback) {
	ecKeyPair = authtool.generateKeyPair();
	userId = bs58.encode(Buffer.from(authtool.getSHA256(ecKeyPair.ecpubhex), 'hex'));

	let options = {
		uri: AUTH_URL,
		method: 'POST',
		body: {
			csr: authtool.generateCSR(ecKeyPair, userId),
			phone: '010-0000-0000'
		},
		json: true
	};

	request(options, function(err, response, body) {
		console.log(body.message);
		certificate = body.certPem;

		keyExService(callback);
	});
}

function keyExService(callback) {
	console.log('[SEND] MSG_JOIN');
	stub.keyExService(generateMsgJoin(), function(err, reply) {
		if (err) {
			console.log('[ERROR]' + err);
			callback(err);
			return;
		}

		console.log('[RECV] MSG_CHALLENGE');
		let msgChallenge = packer.unpack(reply.message);
		console.log('[SEND] MSG_RESPONSE1');
		stub.keyExService(generateMsgRes1(msgChallenge.body.mn), function(err, reply) {
			if (err) {
				console.log('[ERROR]' + err);
				callback(err);
				return;
			}

			console.log('[RECV] MSG_RESPONSE2');
			let msgRes2 = packer.unpack(reply.message);
			console.log('[SEND] MSG_SUCCESS');
			stub.keyExService(generateMsgSuccess(msgRes2.body.dh.x, msgRes2.body.dh.y), function(err, reply) {
				if (err) {
					console.log('[ERROR]' + err);
					callback(err);
					return;
				}

				console.log('[RECV] MSG_ACCEPT');
				let msgAccept = packer.unpack(reply.message);

				console.log('=====(Ready For Signing)====');
				let identity = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Identity', bs58.decode(userId));
				let call = stub.pushService(identity);

				call.on('data', function(msg) {
					console.log('[RECV] MSG_REQ_SSIG');
					let msgReqSsig = packer.unpack(msg.message);

					console.log('[SEND] MSG_SSIG');
					stub.signerService(generateMsgSsig(msgReqSsig.body), function(err, reply) {
						if (err) {
							console.log('[ERROR]' + err);
							callback(err);
							return;
						}

						console.log('[RECV] STATUS: ' + reply.status);
					});
				});
				call.on('error', function(err) {
					console.log('[ERROR]' + err);
					callback(err);
					return;
				});
				call.on('end', callback);
			});
		});
	});
}

function generateMsgJoin() {
	let msg = {};
	msg.time = authtool.getTimestamp();
	msg.world = packer.WORLD_ID;
	msg.chain = packer.CHAIN_ID;
	msg.user = userId;
	msg.merger = bs58.encode(new Buffer.allocUnsafe(64).fill(0));

	let packedMsg = packer.pack(packer.MSG_TYPE.MSG_JOIN, msg, bs58.decode(userId));

	var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Message', packedMsg);
	return grpcMsg;
}

function generateMsgRes1(mergerNonce) {
	userNonce = authtool.getRandomBase64(32);

	let msg = {};
	msg.time = authtool.getTimestamp();
	msg.un = userNonce;

	msg.dh = {
		x: authtool.getPubPoint(ecKeyPair).x,
		y: authtool.getPubPoint(ecKeyPair).y
	};

	msg.user = {
		id: userId,
		pk: certificate,
		sig: authtool.signECDSA(
			ecKeyPair,
			Buffer.concat([
				Buffer.from(mergerNonce, 'base64'),
				Buffer.from(userNonce, 'base64'),
				Buffer.from(msg.dh.x, 'hex'),
				Buffer.from(msg.dh.y, 'hex'),
				authtool.intToDoubleBytes(msg.time)
			])
		)
	};

	let packedMsg = packer.pack(packer.MSG_TYPE.MSG_RESPONSE_1, msg, bs58.decode(userId));

	var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Message', packedMsg);
	return grpcMsg;
}

function generateMsgSuccess(mx, my) {
	secretKey = authtool.getSecret(ecKeyPair, '04' + mx + my);

	let msg = {};
	msg.time = authtool.getTimestamp();
	msg.user = userId;
	msg.mode = 'all';
	msg.val = true;

	let packedMsg = packer.pack(packer.MSG_TYPE.MSG_SUCCESS, msg, bs58.decode(userId), secretKey);

	var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Message', packedMsg);
	return grpcMsg;
}

function generateMsgSsig(msgReqSsig) {
	let target = Buffer.concat([
		bs58.decode(msgReqSsig.block.id),
		Buffer.from(msgReqSsig.block.txroot, 'base64'),
		Buffer.from(msgReqSsig.block.usroot, 'base64'),
		Buffer.from(msgReqSsig.block.csroot, 'base64')
	]);

	let signature = signtool.sign(ecKeyPair, authtool.getSHA256(target));
	let msg = {};
	msg.block = {
		id: msgReqSsig.block.id
	};
	msg.signer = {
		id: userId,
		sig: signature
	};

	let packedMsg = packer.pack(packer.MSG_TYPE.MSG_SSIG, msg, bs58.decode(userId), secretKey);

	var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, 'grpc_user.Message', packedMsg);
	return grpcMsg;
}

function main() {
	argv = tools.argvParser(process.argv);

	if (!argv.ok) {
		tools.printHowToUse();
		return false;
	}
	var add = argv.addr + ':' + argv.port;
	stub = new grpc_user.TethysUserService(add, grpc.credentials.createInsecure());

	async.series([ init ]);
}

if (require.main === module) {
	main();
}

exports.init = init;
exports.keyExService = keyExService;
