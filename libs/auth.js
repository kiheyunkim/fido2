/*
 * @license
 * Copyright 2019 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
const express = require('express');
const router = express.Router();
const blockchain = require('./blockchain');
const crypto = require('crypto');
const { Fido2Lib } = require('fido2-lib');
const { coerceToBase64Url, coerceToArrayBuffer} = require('fido2-lib/lib/utils');
      
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config()

let init = async ()=>{
  await blockchain.init();

  if((await blockchain.checkUserExist('갓대1')).result === 'fail'){
    console.log('해당 id 없음');
  }else{
    console.log('해당 id 있음');
  }

  await blockchain.add_member('갓대1','갓대','갓씨발대','1234');

  if((await blockchain.checkUserExist('갓대1')).result === 'fail'){
    console.log('해당 id 없음');
  }else{
    console.log('해당 id 있음');
  }

  await blockchain.change_Public_Key('갓대1','1234444444444');

  console.log((await blockchain.checkUserExist('갓대1').result));
  
  if((await blockchain.get_doc('갓대1')).result === 'fail'){
    console.log('해당 문서 없음');
  }else{
    console.log('해당 문사 있음');
  }
  
  await blockchain.add_doc('갓대1','4','3','2','1');

  if((await blockchain.get_doc('갓대2')).result === 'fail'){
    console.log('해당 문서 없음');
  }else{
    console.log('해당 문사 있음');
  }
}

init();

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

  const id = req.body.id;
  const username = req.body.username;
  const idPart1 = req.body.idPart1;
  const idPart2 = req.body.idPart2;

  //세션에 가입 요청한 id 기록
  req.session.name = id;
  //ToDo: id 중복 검사 - 블록체인에서 검사할 것.
  if(await blockchain.checkUserExist(id)){
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
    res.status(400).send({ error: e });
  }
});

router.post('/registerResponse', async (req, res) => {
  const id = req.session.name;
  const challenge = coerceToArrayBuffer(req.body.challenge, 'challenge');

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

    let inputres = await blockchain.change_Public_Key(id,JSON.stringify(credential));
    console.log(inputres);
    let result = JSON.parse((await blockchain.getAllUser()).result);
    console.log(result);

    res.json({result:"ok"});

  } catch (e) {
    req.session.name = undefined;
    res.status(400).send({ error: e.message });
  }
  finally{
    req.session.name = undefined;
  }
});

router.post('/signinRequest', async (req, res) => {
  try {
    let id = req.body.id;
    req.session.name = id;

    let result = (await blockchain.getUserbyId(id)).result;

    if(result === undefined){
      res.json({error: '등록 되지 않은 아이디 입니다.'});
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

    console.log("로그인 요청 끝");
    res.json(response);
  } catch (e) {
    res.status(400).json({ error: e });
  }
});

router.post('/signinResponse', async (req, res) => {
    let id = req.session.name;
    let user = (await blockchain.getUserbyId(id)).result;

    if(user === undefined){
      res.json({error: '등록 되지 않은 아이디 입니다.'});
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

    res.json({result:'ok'});
  } catch (e) {
    res.status(400).json({ error: e });
  }
});

module.exports = router;