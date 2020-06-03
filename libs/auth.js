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
const session = require('express-session');
const router = express.Router();
const crypto = require('crypto');
const { Fido2Lib } = require('fido2-lib');
const { coerceToBase64Url,
        coerceToArrayBuffer
      } = require('fido2-lib/lib/utils');
      
const fs = require('fs');
const dotenv = require('dotenv');
dotenv.config()


const low = require('lowdb');
if (!fs.existsSync('./.data')) {
  fs.mkdirSync('./.data');
}

const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);

const f2l = new Fido2Lib({
    timeout: 30*1000*60,
    rpId: process.env.HOSTNAME,
    rpName: "WebAuthn Codelab",
    challengeSize: 32,
    cryptoParams: [-7]
});


console.log(process.env.ANDROID_SHA256HASH);
console.log(process.env.ANDROID_PACKAGENAME);

db.defaults({
  users: []
}).write();

const csrfCheck = (req, res, next) => {
  if (req.header('X-Requested-With') != 'XMLHttpRequest') {
    res.status(400).json({error: 'invalid access.'});
    return;
  }
  next();
};

/**
 * Checks CSRF protection using custom header `X-Requested-With`
 * If cookie doesn't contain `username`, consider the user is not authenticated.
 **/
const sessionCheck = (req, res, next) => {
  if (!req.cookies['signed-in']) {
    res.status(401).json({error: 'not signed in.'});
    return;
  }
  next();
};

router.post('/getKeys', csrfCheck, sessionCheck, (req, res) => {
  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();
  res.json(user || {});
});

/**
 * Removes a credential id attached to the user
 * Responds with empty JSON `{}`
 **/
router.post('/removeKey', csrfCheck, sessionCheck, (req, res) => {
  const credId = req.query.credId;
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();

  const newCreds = user.credentials.filter(cred => {
    // Leave credential ids that do not match
    return cred.credId !== credId;
  });

  db.get('users')
    .find({ username: username })
    .assign({ credentials: newCreds })
    .write();

  res.json({});
});



/**
 * Authenticate the user.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       authenticatorData: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/

router.post('/signinResponse', csrfCheck, async (req, res) => {
  // Query the user

  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();

  let credential = null;
  for (let cred of user.credentials) {
    if (cred.credId === req.body.id) {
      credential = cred;
    }
  }

  try {
    if (!credential) {
      throw 'Authenticating credential not found.';
    }

    const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');
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
      userHandle: coerceToArrayBuffer(user.id, 'userHandle')
    };
    const result = await f2l.assertionResult(clientAssertionResponse, assertionExpectations);

    credential.prevCounter = result.authnrData.get("counter");

    db.get('users')
      .find({ id: req.cookies.id })
      .assign(user)
      .write();

    res.clearCookie('challenge');
    res.cookie('signed-in', 'yes');
    res.json(user);
  } catch (e) {
    console.log(e);
    res.clearCookie('challenge');
    res.status(400).json({ error: e });
  }
});

router.get('/signout', (req, res) => {
  // Remove cookies
  res.clearCookie('username');
  res.clearCookie('signed-in');
  // Redirect to `/`
  res.redirect(302, '/');
});

//이 밑으로는 공식
 router.post('/registerRequest', async (req, res) => {
   console.log("register Start");
  const id = req.body.id;
  const username = req.body.username;
  const idPart1 = req.body.idPart1;
  const idPart2 = req.body.idPart2;

  /*
  if(idPart1.length !== 6 || idPart2.length !== 7 || !Number.isInteger(idPart1) || !Number.isInteger(idPart1)){
    res.status(400).send({ error: "invalid_id" });
    return;
  }
  */

  //세션에 가입 요청한 id 기록
  req.session.name = id;
  //ToDo: id 중복 검사 - 블록체인에서 검사할 것.
  let checker = db.get('users')
                  .find({id:id})
                  .value();

  if(checker !== undefined){
    res.status(400).send({ error: "existed_id" });
    return;
  }

  //본인 정보 중복 검사.
  //ToDo: id 중복 검사 - 블록체인에서 검사할 것.
  let checkInfo = db.get('users')
                    .find({username:username, identity:(idPart1 + "-" + idPart2)})
                    .value();
  if(checkInfo !== undefined){
    res.status(400).send({ error: "existed_info" });
    return;
  }

  let user = {
    id:id,
    username: username,
    identity : (idPart1 + "-" + idPart2),
    credential: undefined
  }
  console.log(user);
  try {
    const response = await f2l.attestationOptions();
    response.user = {
      displayName: 'No name',
      id: user.id,
      name: user.username
    };

    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    res.cookie('challenge', response.challenge);

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

    db.get('users')
    .push(user)
    .write();

    console.log(response);
    res.json(response);
  } catch (e) {
    console.log(e);
    res.status(400).send({ error: e });
  }
});

router.post('/registerResponse', async (req, res) => {
  const id = req.session.name;
  const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');

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

    const user = db.get('users')
      .find({ id: id })
      .value();

    user.credential = credential;

    db.get('users')
      .find({ id: id })
      .assign(user)
      .write();

    res.clearCookie('challenge');

    console.log(user);
    // Respond with user info
    res.json({result:"ok"});
  } catch (e) {
    console.log(e);
    res.clearCookie('challenge');
    res.status(400).send({ error: e.message });
  }
});

router.post('/signinRequest', async (req, res) => {
  console.log("로그인 요청");
  try {
    let id = req.body.id;
    req.session.loginId = id;

    const user = db.get('users')
    .find({ id: id })
    .value();
   
    if (!user) {
      res.json({error: '등록 되지 않은 아이디 입니다.'});
      return;
    }

    const response = await f2l.assertionOptions();

    response.userVerification = req.body.userVerification || 'preferred';
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    res.cookie('challenge', response.challenge);

    response.allowCredentials = [];
    response.allowCredentials.push({
      id: user.credential.credId,
      type: 'public-key',
      transports: ['internal']
    });

    console.log("로그인 요청 끝");
    res.json(response);
  } catch (e) {
    console.log(e);
    res.status(400).json({ error: e });
  }
});

router.post('/signinResponse', async (req, res) => {

  console.log(req.body);
  // Query the user
  const user = db.get('users')
    .find({ id: req.session.loginId })
    .value();

  let credential = user.credential;

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

    const user = db.get('users')
      .find({ id: id })
      .value();

    user.credential = credential;

    db.get('users')
      .find({ id: id })
      .assign(user)
      .write();

    res.clearCookie('challenge');

    // Respond with user info
    res.json(user);
  } catch (e) {
    console.log(e);
    res.clearCookie('challenge');
    res.status(400).send({ error: e.message });
  }
});

module.exports = router;