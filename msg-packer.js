const protobuf = require('protobufjs');
const cbor = require('ipld-dag-cbor');
const tools = require('./auth-tools.js');
const crypto = require('crypto');

const HEADER_LENGTH = 58;
const WORLD_ID = '_TETHYS_';
const CHAIN_ID = 'TSTCHAIN';
const MSG_TYPE = {
	MSG_TX: 0xb1,
	MSG_REQ_SSIG: 0xb2,
	MSG_SSIG: 0xb3,
	MSG_JOIN: 0x54,
	MSG_CHALLENGE: 0x55,
	MSG_RESPONSE_1: 0x56,
	MSG_RESPONSE_2: 0x57,
	MSG_SUCCESS: 0x58,
	MSG_ACCEPT: 0x59,
	MSG_REQ_TX_CHECK: 0xc0,
	MSG_RES_TX_CHECK: 0xc1,
	MSG_QUERY: 0xc3,
	MSG_RESULT: 0xc4,
	MSG_NULL: 0x00,
	MSG_SETUP_MERGER: 0xe1,
	MSG_ERROR: 0xff
};
const SER_TYPE = {
	CBOR: 0x06,
	NONE: 0xff
};
const MAC_TYPE = {
	HMAC: 0xf1,
	NONE: 0xff
};

const grpcMsgSerializer = function(PROTO_PATH, msgTypeName, packedMsg) {
	const root = protobuf.loadSync(PROTO_PATH);

	// Obtain a message type
	var msgType = root.lookupType(msgTypeName);
	var payload = { message: packedMsg };
	var errMsg = msgType.verify(payload);
	if (errMsg) logger.error('failed to verify payload: ' + errMsg);

	var grpcMsg = msgType.create(payload); // byte packed msg => base64 msg
	return grpcMsg;
};

const pack = function(MSG_TYPE, data, senderId, secret) {
	let serializedData = serialize(data);

	if (secret !== undefined) {
		let header = buildHeaderWithMac(MSG_TYPE, serializedData, senderId);
		let mac = buildHMAC(data, secret);
		return Buffer.concat([ header, serializedData.body, mac ]);
	} else {
		let header = buildHeader(MSG_TYPE, serializedData, senderId);
		return Buffer.concat([ header, serializedData.body ]);
	}
};

const serialize = function(data) {
	let serializedBuffer = new Buffer.from(cbor.util.serialize(data));
	var serializedData = {
		body: serializedBuffer,
		length: serializedBuffer.length
	};

	return serializedData;
};

const buildHeader = function(msgTypeByte, serializedData, senderId) {
	var head = {
		front: buildHeaderFront(msgTypeByte),
		totalLength: tools.intToLongBytes(serializedData.length + HEADER_LENGTH),
		worldId: Buffer.from(WORLD_ID),
		chainId: Buffer.from(CHAIN_ID),
		sender: senderId
	};

	return Buffer.concat([ head.front, head.totalLength, head.worldId, head.chainId, head.sender ], HEADER_LENGTH);
};

const buildHeaderWithMac = function(msgTypeByte, serializedData, senderId) {
	var head = {
		front: buildHeaderFrontWithMac(msgTypeByte),
		totalLength: tools.intToLongBytes(serializedData.length + HEADER_LENGTH),
		worldId: Buffer.from(WORLD_ID),
		chainId: Buffer.from(CHAIN_ID),
		sender: senderId
	};

	return Buffer.concat([ head.front, head.totalLength, head.worldId, head.chainId, head.sender ], HEADER_LENGTH);
};

// build front 6 bytes of the header
const buildHeaderFront = function(msgTypeByte) {
	return new Buffer.from([
		0x50, // 'P'
		0x01, // msg version
		msgTypeByte, // msg type
		MAC_TYPE.NONE, // mac type: NONE
		SER_TYPE.CBOR, // ser type: CBOR
		0x00 // not used
	]);
};

// build front 6 bytes of the header
const buildHeaderFrontWithMac = function(msgTypeByte) {
	return new Buffer.from([
		0x50, // 'P'
		0x01, // msg version
		msgTypeByte, // msg type
		MAC_TYPE.HMAC, // mac type: HMAC
		SER_TYPE.CBOR, // ser type: CBOR
		0x00 // not used
	]);
};

const buildHMAC = function(data, secret) {
	let hmac = crypto.createHmac('sha256', secret);
	hmac.update(data.toString('hex'));
	return Buffer.from(hmac.digest('hex'));
};

const unpack = function(data) {
	let header = recoverHeader(data);

	return {
		header: header,
		body: recoverBody(data, header.totalLength, header.serType)
	};
};

const recoverHeader = function(data) {
	var header = {
		P: data[0],
		version: data[1],
		msgType: data[2],
		macType: data[3],
		serType: data[4],
		notUsed: data[5],
		totalLength: data.readInt32BE(6)
	};
	header.worldId = Buffer.alloc(8);
	header.chainId = Buffer.alloc(8);
	header.sender = Buffer.alloc(32);

	data.copy(header.worldId, 0, 10, 18);
	data.copy(header.chainId, 0, 18, 26);
	data.copy(header.sender, 0, 26, 58);

	return header;
};

const recoverBody = function(data, totalLength, serType) {
	let buffer = Buffer.alloc(totalLength - HEADER_LENGTH);
	data.copy(buffer, 0, HEADER_LENGTH, totalLength);

	if (serType == SER_TYPE.CBOR) {
		return cbor.util.deserialize(buffer);
	} else if (serType == SER_TYPE.NONE) {
		return JSON.parse(buffer);
	}
};

const self = (module.exports = {
	grpcMsgSerializer: grpcMsgSerializer,
	pack: pack,
	unpack: unpack,
	MSG_TYPE: MSG_TYPE,
	WORLD_ID: WORLD_ID,
	CHAIN_ID: CHAIN_ID
});
