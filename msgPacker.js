const protobuf = require('protobufjs');
const cbor = require('ipld-dag-cbor');
var tools = require('./authTools.js');

const HEADER_LENGTH = 58;
const WORLD_ID = "_TETHYS_";
const CHAIN_ID = "TSTCHAIN";
const MSG_TYPE = {
  MSG_TX: 0xB1,
  MSG_REQ_SSIG: 0xB2,
  MSG_SSIG: 0xB3,
  MSG_JOIN: 0x54,
  MSG_CHALLENGE: 0x55,
  MSG_RESPONSE_1: 0x56,
  MSG_RESPONSE_2: 0x57,
  MSG_SUCCESS: 0x58,
  MSG_ACCEPT: 0x59,
  MSG_REQ_TX_CHECK: 0xC0,
  MSG_RES_TX_CHECK: 0xC1,
  MSG_QUERY: 0xC3,
  MSG_RESULT: 0xC4,
  MSG_NULL: 0x00,
  MSG_SETUP_MERGER: 0xE1,
  MSG_ERROR: 0xFF  
};
const SER_TYPE = {
	CBOR: 0x06,
	NONE: 0xFF
};

const grpcMsgSerializer = function(PROTO_PATH, msgTypeName, packedMsg) {
	const root = protobuf.loadSync(PROTO_PATH);

	// Obtain a message type
	var msgType = root.lookupType(msgTypeName);
	var payload = {message: packedMsg};
	var errMsg = msgType.verify(payload);
	if (errMsg) logger.error("failed to verify payload: " + errMsg);

	var grpcMsg = msgType.create(payload);	// byte packed msg => base64 msg
	return grpcMsg;
};

const pack = function(MSG_TYPE, data, senderId) {
  let serializedData = serialize(data);
  let header = buildHeader(MSG_TYPE, serializedData, senderId);

  return Buffer.concat([header, serializedData.body]);
};

const serialize = function(data) {
  let serializedBuffer = new Buffer.from(cbor.util.serialize(data));
  var serializedData = {
    body: serializedBuffer,
    length: serializedBuffer.length
  };

  return serializedData
};

const buildHeader = function(msgTypeByte, serializedData, senderId) {
  var head = {
    front: buildHeaderFront(msgTypeByte),
    totalLength: tools.intToLongBytes(serializedData.length + HEADER_LENGTH),
    worldId: Buffer.from(WORLD_ID),
    chainId: Buffer.from(CHAIN_ID),
    sender: senderId
  };

  return Buffer.concat([
    head.front, head.totalLength, head.worldId, head.chainId, head.sender
  ], serializedData.length + HEADER_LENGTH);
};

// build front 6 bytes of the header
const buildHeaderFront = function(msgTypeByte) {
  return new Buffer.from([
    0x50            // 'P'
		,0x01           // msg version
    ,msgTypeByte    // msg type
		,0xFF           // mac type: NONE
		,SER_TYPE.CBOR  // ser type: CBOR
		,0x00           // not used
  ]);
};

const self = module.exports = {
  grpcMsgSerializer: grpcMsgSerializer,
  pack: pack,
  MSG_TYPE : MSG_TYPE,
  WORLD_ID: WORLD_ID,
  CHAIN_ID: CHAIN_ID
};