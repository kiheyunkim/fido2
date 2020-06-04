const express = require('express');
const router = express.Router();
const blockchain = require('./blockchain');
const fileGenerator = require('./../file/fileGenerator')
const { Fido2Lib } = require('fido2-lib');
const { coerceToBase64Url, coerceToArrayBuffer} = require('fido2-lib/lib/utils');
      
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config();

const f2l = new Fido2Lib({
  timeout: 30*1000*60,
  rpId: process.env.HOSTNAME,
  rpName: "WebAuthn Codelab",
  challengeSize: 32,
  cryptoParams: [-7]
});

//OK
//이 밑으로는 공식
 router.post('/registerRequest', async (req, res) => {

  console.log("회원가입 시작");
  console.log(req.body);

  const id = req.body.id;
  const username = req.body.username;
  const idPart1 = req.body.idPart1;
  const idPart2 = req.body.idPart2;

  //세션에 가입 요청한 id 기록
  req.session.name = id;
  //ToDo: id 중복 검사 - 블록체인에서 검사할 것.
  if(await blockchain.checkUserExist(id)) {
    res.status(400).send({ error: "existed_id" });
    return;
  }

  //본인 정보 중복 검사.
  const identity = idPart1 + '-' + idPart2;
  let isVerified = true;
  let result = JSON.parse((await blockchain.getAllUser()).result);
  result.forEach(element => {
    if(element.ID_Number === identity){
      isVerified = false;
      return false;
    }
  });

  if(!isVerified){
    res.status(400).send({ error: "existed_info" });
    return;
  }

  let user = {
    id:id,
    username: username,
    identity : identity,
    credential: ""
  }
  
  try {
    const response = await f2l.attestationOptions();
    response.user = {
      displayName: 'No name',
      id: user.id,
      name: user.username
    };

    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    req.session.challenge = response.challenge;
    
    response.pubKeyCredParams = [];
    const params = [-7, -257];
    for (let param of params) {
      response.pubKeyCredParams.push({type:'public-key', alg: param});
    }
    const as = {}; // authenticatorSelection
    const aa = req.body.authenticatorSelection.authenticatorAttachment;
    const rr = req.body.authenticatorSelection.requireResidentKey;
    const uv = req.body.authenticatorSelection.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.authenticatorAttachment = aa;
    }
    if (rr && typeof rr == 'boolean') {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      response.attestation = cp;
    }

    await blockchain.add_member(id,username,identity,"");
    res.json(response);
  } catch (e) {
    console.log(e);
    res.status(400).json({ 'result': e });
  }
});

router.post('/registerResponse', async (req, res) => {
  const id = req.session.name;
  const challenge = coerceToArrayBuffer(req.body.challenge, 'challenge');

  console.log("회원가입 반응");
  console.log(req.body);

  try {
    const clientAttestationResponse = { response: {} };
    clientAttestationResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAttestationResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAttestationResponse.response.attestationObject =
      coerceToArrayBuffer(req.body.response.attestationObject, "attestationObject");

    let origin = '';
    if (req.get('User-Agent').indexOf('okhttp') > -1) {
      const octArray = process.env.ANDROID_SHA256HASH.split(':').map(h => parseInt(h, 16));
      const androidHash = coerceToBase64Url(octArray, 'Android Hash');
      origin = `android:apk-key-hash:${androidHash}`; // TODO: Generate
    } else {
      origin = `https://${req.get('host')}`;
    }

    const attestationExpectations = {
      challenge: challenge,
      origin: origin,
      factor: "either"
    };

    const regResult = await f2l.attestationResult(clientAttestationResponse, attestationExpectations);
    const credential = {
      credId: coerceToBase64Url(regResult.authnrData.get("credId"), 'credId'),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      aaguid: coerceToBase64Url(regResult.authnrData.get("aaguid"), 'aaguid'),
      prevCounter: regResult.authnrData.get("counter")
    };

    await blockchain.change_Public_Key(id,JSON.stringify(credential));
    let person = JSON.parse((await (await blockchain.getUserbyId(id))).result);
    await fileGenerator.generate(id,person.Name);
    
    res.json({'result':"ok"});

  } catch (e) {
    req.session.name = undefined;
    console.log(e);
    res.status(400).json({ 'result': e.message });
  }
  finally{
    req.session.name = undefined;
  }
});

router.post('/signinRequest', async (req, res) => {
  try {
    let id = req.body.id;
    console.log(req.body);
    req.session.name = id;

    let result = (await blockchain.getUserbyId(id)).result;

    if(result === undefined){
      res.json({result: '등록 되지 않은 아이디 입니다.'});
      return;  
    }
  
    let user = JSON.parse(result);
    let credential = JSON.parse(user.HashKey);

    const response = await f2l.assertionOptions();

    response.userVerification = req.body.userVerification || 'preferred';
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');

    response.allowCredentials = [];
    response.allowCredentials.push({
      id: credential.credId,
      type: 'public-key',
      transports: ['internal']
    });

    res.json(response);
  } catch (e) {
    res.status(400).json({ result: e });
  }
});

router.post('/signinResponse', async (req, res) => {
    let id = req.session.name;
    let user = (await blockchain.getUserbyId(id)).result;

    if(user === undefined){
      res.json({result: '등록 되지 않은 아이디 입니다.'});
      return;  
    }

    user = JSON.parse(user);
    console.log("user user");
    console.log(user);
    
    try {
      let credential = JSON.parse(user.HashKey);
       if (!credential) {
          throw 'Authenticating credential not found.';
    }

    const challenge = coerceToArrayBuffer(req.body.challenge, 'challenge');
    const origin = `https://${req.get('host')}`; // TODO: Temporary work around for scheme

    const clientAssertionResponse = { response: {} };
    clientAssertionResponse.rawId =
      coerceToArrayBuffer(req.body.rawId, "rawId");
    clientAssertionResponse.response.clientDataJSON =
      coerceToArrayBuffer(req.body.response.clientDataJSON, "clientDataJSON");
    clientAssertionResponse.response.authenticatorData =
      coerceToArrayBuffer(req.body.response.authenticatorData, "authenticatorData");
    clientAssertionResponse.response.signature =
      coerceToArrayBuffer(req.body.response.signature, "signature");
    clientAssertionResponse.response.userHandle =
      coerceToArrayBuffer(req.body.response.userHandle, "userHandle");
    const assertionExpectations = {
      challenge: challenge,
      origin: origin,
      factor: "either",
      publicKey: credential.publicKey,
      prevCounter: credential.prevCounter,
      userHandle: coerceToArrayBuffer(id, 'userHandle')
    };
    const result = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    credential.prevCounter = result.authnrData.get("counter");
    req.session.auth = true;
    req.session.authId = id;
    console.log(id + " : login OK");
    
    res.json({'result':'ok'});

  } catch (e) {
    res.status(400).json({'result': e });
  }
});

module.exports = router;