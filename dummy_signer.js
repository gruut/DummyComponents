var PROTO_PATH = __dirname + '/UserService.proto';

var tools = require('./authTools.js');
var packer = require('./msgPacker.js');

var async = require('async');
var bs58 = require('bs58');
var path = require('path');
var grpc = require('grpc');
var protoLoader = require('@grpc/proto-loader');
var packageDefinition = protoLoader.loadSync(
    PROTO_PATH,
    {keepCase: true,
     longs: String,
     enums: String,
     defaults: true,
     oneofs: true
    });
var grpc_user = grpc.loadPackageDefinition(packageDefinition).grpc_user;
var stub = new grpc_user.TethysUserService('0.0.0.0:8089',
                                       grpc.credentials.createInsecure());

var COORD_FACTOR = 1e7;

/**
 *  rpc PushService (Identity) returns (stream Message) {}
    rpc KeyExService (Request) returns (Reply) {}
    rpc UserService (Request) returns (Reply) {}
    rpc SignerService (Request) returns (Reply) {}
 */

var ecKeyPair;
var userId;
var userNonce;

function init(callback) {
  ecKeyPair = tools.generateKeyPair();
  userId = bs58.encode(Buffer.from(tools.getSHA256(ecKeyPair.ecpubhex), 'hex'))

  keyExService(callback);
}

function keyExService(callback) {
  console.log('[SEND] MSG_JOIN');
  stub.KeyExService(generateMsgJoin(), function(err, reply) {
    if (err)  {
      console.log('[ERROR]' + error);
      callback(error);
      return;
    }
    
    console.log('SUCCESS');
  });
}

function generateMsgJoin() {
  let msg = {};
  msg.time = tools.getTimestamp();
  msg.world = packer.WORLD_ID;
  msg.chain = packer.CHAIN_ID;
  msg.user = userId;
  msg.merger = bs58.encode(new Buffer.allocUnsafe(64).fill(0));
  
  let packedMsg = packer.pack(
    packer.MSG_TYPE.MSG_JOIN,
    msg,
    bs58.decode(userId)
  );

  var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, "grpc_user.Message", packedMsg);
  return grpcMsg;
}

function generateMsgRes1(mergerNonce) {
  userNonce = tools.getRandomBase64(32);

  let msg = {};
  msg.time = tools.getTimestamp();
  msg.un = userNonce;

  msg.dh = {
    x: ecKeyPair.getPublicKeyXYHex().x,
    y: ecKeyPair.getPublicKeyXYHex().y
  };

  msg.user = {
    id: userId,
    pk: tools.generateSelfCert(ecKeyPair),
    sig: tools.signECDSA(ecKeyPair, 
        Buffer.concat([
          Buffer.from(mergerNonce, 'base64'),
          Buffer.from(userNonce, 'base64'),
          Buffer.from(msg.dh.x, 'hex'),
          Buffer.from(msg.dh.y, 'hex'),
          tools.intToLongBytes(msg.time)
        ])
      )
  };
}

function main() {
  async.series([
    init
  ]);
}

if (require.main === module) {
  main();
}

exports.init = init;
exports.keyExService = keyExService;