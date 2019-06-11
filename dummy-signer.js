var PROTO_PATH = __dirname + '/UserService.proto';

var tools = require('./auth-tools.js');
var packer = require('./msg-packer.js');

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
var secretKey;

function init(callback) {
  ecKeyPair = tools.generateKeyPair();
  userId = bs58.encode(Buffer.from(tools.getSHA256(ecKeyPair.ecpubhex), 'hex'))

  keyExService(callback);
}

function keyExService(callback) {
  console.log('[SEND] MSG_JOIN');
  stub.keyExService(generateMsgJoin(), function(err, reply) {
    if (err)  {
      console.log('[ERROR]' + err);
      callback(err);
      return;
    }

    console.log('[RECV] MSG_CHALLENGE');
    let msgChallenge = packer.unpack(reply.message);
    console.log('[SEND] MSG_RESPONSE1');
    stub.keyExService(generateMsgRes1(msgChallenge.body.mn), function(err, reply) {
      if (err)  {
        console.log('[ERROR]' + err);
        callback(err);
        return;
      }

      console.log('[RECV] MSG_RESPONSE2');
      let msgRes2 = packer.unpack(reply.message);
      console.log('[SEND] MSG_SUCCESS');
      stub.keyExService(generateMsgSuccess(msgRes2.body.dh.x, msgRes2.body.dh.y), function(err, reply) {
        if (err)  {
          console.log('[ERROR]' + err);
          callback(err);
          return;
        }

        console.log('[RECV] MSG_ACCEPT');
        let msgAccept = packer.unpack(reply.message);

        console.log('=====(Ready For Signing)====');
        let identity = packer.grpcMsgSerializer(PROTO_PATH, "grpc_user.Identity", bs58.decode(userId));
        let call = stub.pushService(identity);
        
        call.on('data', function(feature) {
            console.log('[RECV] MSG_REQ_SSIG');
        });
        call.on('error', function(err) {
          console.log('[ERROR]' + err);
          callback(err);
          return;
        })
        call.on('end', callback);
      });
    });
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
    x: tools.getPubPoint(ecKeyPair).x,
    y: tools.getPubPoint(ecKeyPair).y
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

  let packedMsg = packer.pack(
    packer.MSG_TYPE.MSG_RESPONSE_1,
    msg,
    bs58.decode(userId)
  );

  var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, "grpc_user.Message", packedMsg);
  return grpcMsg;
}

function generateMsgSuccess(mx, my) {
  secretKey = tools.getSecret(ecKeyPair, "04" + mx + my)

  let msg = {};
  msg.time = tools.getTimestamp();
  msg.user = userId;
  msg.mode = "all";
  msg.val = true;

  let packedMsg = packer.pack(
    packer.MSG_TYPE.MSG_SUCCESS,
    msg,
    bs58.decode(userId),
    secretKey
  );

  var grpcMsg = packer.grpcMsgSerializer(PROTO_PATH, "grpc_user.Message", packedMsg);
  return grpcMsg;
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