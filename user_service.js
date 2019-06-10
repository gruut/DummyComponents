/*
 *
 * Copyright 2015 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

var PROTO_PATH = __dirname + '/UserService.proto';
var packer = require("./packer.js");
var tools = require("./mytools.js");    
var bs58 = require('bs58');
var _ = require('lodash');
var grpc = require('grpc');
var protoLoader = require('@grpc/proto-loader');
const readline = require('readline');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

var packageDefinition = protoLoader.loadSync(
    PROTO_PATH,
    {keepCase: true,
     longs: String,
     enums: String,
     defaults: true,
     oneofs: true
    });
var grpc_user = grpc.loadPackageDefinition(packageDefinition).grpc_user;
var MERGER_ID = bs58.encode(Buffer.from(tools.getSHA256("NODE_JS_MERGER_EMUL"), 'hex'))

var height = 0;
var pushService;
function PushService(call) {
  height = 0;
  pushService = call;
  console.log("[READY] PushService")
  recursiveAsyncReadLine(call);
}

var recursiveAsyncReadLine = function (call) {
  rl.question('If you want to send MSG_REQ_SSIG, please enter any key(exit): ', function (answer) {
    if (answer == 'exit') { //we need some base case, for recursion
      call.end();
      return rl.close(); //closing RL and returning from function.
    }
    height++;
    var msg = generateMsgReqSsig()
    call.write(msg)
  });
};

function generateMsgReqSsig() {
  var ecdsa = tools.getECDSAKeyPair();

  let msg = {};
  msg.block = {};
  msg.producer = {};
  msg.block.time = tools.getTimestamp();
  msg.block.world = "_TETHYS_";
  msg.block.chain = "TSTCHAIN";
  msg.block.height = height;
  msg.block.previd = bs58.encode(Buffer.from(tools.getSHA256((height-1)+ ""), 'hex'))
  msg.block.txroot = tools.getRandomBase64(32);
  msg.block.usroot = tools.getRandomBase64(32);
  msg.block.csroot = tools.getRandomBase64(32);
  msg.producer.id = MERGER_ID
  
  msg.block.id = bs58.encode(Buffer.from(tools.getSHA256(
    Buffer.concat([
      bs58.decode(msg.producer.id),
      packer.getBufferedTimestamp(msg.block.time),
      Buffer.from(msg.block.world),
      Buffer.from(msg.block.chain),
      packer.getBufferedTimestamp(msg.block.height),
      bs58.decode(msg.block.previd)
    ])
  ), 'hex'))
  msg.producer.sig = tools.signECDSA(ecdsa, 
    tools.getSHA256(
      Buffer.concat([
        bs58.decode(msg.block.id),
        Buffer.from(msg.block.txroot, 'base64'),
        Buffer.from(msg.block.usroot, 'base64'),
        Buffer.from(msg.block.csroot, 'base64')
      ], 128))
    );

  let msg_pack = packer.pack(
    packer.MSG_TYPE.MSG_REQ_SSIG, 
    msg, 
    bs58.decode(MERGER_ID)
  );
  var message = packer.protobuf_msg_serializer(PROTO_PATH, "grpc_user.Message", msg_pack)

  console.log("[SEND] MSG_REQ_SSIG")
  return message;
}

function SignerService(call, callback) {
  callback(null, getMessage(call.request));
  recursiveAsyncReadLine(pushService); //Calling this function again to ask new question
}

function keyExService(call, callback) {
  callback(null, getMessage(call.request));
}

function getMessage(request) {
  let receivedMsg = packer.unpack(request.message)
  
  if (receivedMsg.header.msg_type == packer.MSG_TYPE.MSG_JOIN) {
    console.log("[RECV] MSG_JOIN")
    return generateMsgChallenge(receivedMsg.body.user)
  } else if (receivedMsg.header.msg_type == packer.MSG_TYPE.MSG_RESPONSE_1) {
    console.log("[RECV] MSG_RESPONSE_1")
    return generateMsgResponse2(receivedMsg.body.un)
  } else if (receivedMsg.header.msg_type == packer.MSG_TYPE.MSG_SUCCESS) {
    console.log("[RECV] MSG_SUCCESS")
    return generateMsgAccept()
  } else if (receivedMsg.header.msg_type == packer.MSG_TYPE.MSG_SSIG) {
    console.log("[RECV] MSG_SSIG")
    return responseToMsgSsig()
  } else {
    console.log("[RECV]" + JSON.stringify(receivedMsg))
    return responseError();
  }
}

function responseToMsgSsig() {
  reply = {
    status: "SUCCESS",
    message: ""
  };

  console.log("[SEND] MSG_SSIG STATUS")
  return reply;
}

function responseError() {
  reply = {
    status: "UNKNOWN",
    message: ""
  };

  console.log("[SEND] ERROR")
  return reply;
}

var merger_nonce;
function generateMsgChallenge(user_id) {
  merger_nonce = tools.getRandomBase64(32);

  let msgChallenge = {};
  msgChallenge.time = tools.getTimestamp()
  msgChallenge.user = user_id
  msgChallenge.merger = MERGER_ID
  msgChallenge.mn = merger_nonce;

  let msg_pack = packer.pack(
    packer.MSG_TYPE.MSG_CHALLENGE, 
    msgChallenge, 
    bs58.decode(MERGER_ID)
  );

  reply = {
    status: "SUCCESS",
    message: msg_pack
  };

  console.log("[SEND] MSG_CHALLENGE")
  return reply;
}

function generateMsgResponse2(user_nonce) {
  var ecdsa = tools.getECDSAKeyPair();

  let msg = {};
  msg.time = tools.getTimestamp()
  msg.dh = {};
  msg.dh.x = ecdsa.getPublicKeyXYHex().x
  msg.dh.y = ecdsa.getPublicKeyXYHex().y
  msg.merger = {};
  msg.merger.id = MERGER_ID
  msg.merger.cert = tools.createCert(ecdsa)

  msg.merger.sig = tools.signECDSA(ecdsa, 
    Buffer.concat([
      Buffer.from(merger_nonce, 'base64'),
      Buffer.from(user_nonce, 'base64'),
      Buffer.from(msg.dh.x, 'hex'),
      Buffer.from(msg.dh.y, 'hex'),
      packer.getBufferedTimestamp(msg.time)],
      136)
  )

  let msg_pack = packer.pack(
    packer.MSG_TYPE.MSG_RESPONSE_2,
    msg,
    bs58.decode(MERGER_ID)
  );
  
  reply = {
    status: "SUCCESS",
    message: msg_pack
  };
  
  console.log("[SEND] MSG_RESPONSE_2")
  return reply;
}

function generateMsgAccept() {
  let msg = {};
  msg.time = tools.getTimestamp();
  msg.merger = MERGER_ID
  msg.val = true

  let msg_pack = packer.pack(
    packer.MSG_TYPE.MSG_ACCEPT,
    msg,
    bs58.decode(MERGER_ID)
  );

  reply = {
    status: "SUCCESS",
    message: msg_pack
  };
  
  console.log("[SEND] MSG_ACCEPT")
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
    SignerService: SignerService
  });
  return server;
}

if (require.main === module) {
  // If this is run as a script, start a server on an unused port
  var routeServer = getServer();
  routeServer.bind('0.0.0.0:8089', grpc.ServerCredentials.createInsecure());
  routeServer.start();
}

exports.getServer = getServer;
