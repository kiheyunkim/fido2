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
const crypto = require('crypto');
const { Fido2Lib } = require('fido2-lib');
const { coerceToBase64Url,
        coerceToArrayBuffer
      } = require('fido2-lib/lib/utils');
const fs = require('fs');

const low = require('lowdb');

if (!fs.existsSync('./.data')) {
  fs.mkdirSync('./.data');
}

const FileSync = require('lowdb/adapters/FileSync');
const adapter = new FileSync('.data/db.json');
const db = low(adapter);
db.defaults({
  users: []
}).write();

const f2l = new Fido2Lib({
    timeout: 30*1000*60,
    rpId: process.env.HOSTNAME,
    rpName: "WebAuthn Codelab",
    challengeSize: 32,
    cryptoParams: [-7]
});

router.use(express.json());

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

router.post('/registerCredentials',csrfCheck, (request,response)=>{
    const username = request.body.info.username;
    const identifypart1 = request.body.info.identifypart1;
    const identifypart2 = request.body.info.identifypart2;

    //Todo : 블록체인에 이름과 주민번호를 이용해서 찾는다.
    const user = db.get('users')
                .find({username:username, identify :(identifypart1 + '-' + identifypart2)})
                .value();
    ////////////////////////////////////////////////////

    if(user !== undefined){
      response.json({result:'Already Exist'});
    }

    
    //base64로 변환한 32자리의 랜덤 바이트를 id로 집어 넣는다.
    //이름은 특별한 의미가 없음. 그냥 base64로 암호화 한다는 것만 중요.
    user = {
      username: username,
      id: coerceToBase64Url(crypto.randomBytes(32), 'user.id'),
      identify:identifypart1 + "-" + identifypart2,
      credentials: []
    }

    try {
      const res = await f2l.attestationOptions();
      res.user = {
        displayName: 'No name',
        id: user.id,
        name: user.username
      };
      res.challenge = coerceToBase64Url(res.challenge, 'challenge');
      res.cookie('challenge', res.challenge);
      res.excludeCredentials = [];
      if (user.credentials.length > 0) {
        for (let cred of user.credentials) {
          res.excludeCredentials.push({
            id: cred.credId,
            type: 'public-key',
            transports: ['internal']
          });
        }
      }
      res.pubKeyCredParams = [];
      const params = [-7, -257];
      for (let param of params) {
        res.pubKeyCredParams.push({type:'public-key', alg: param});
      }
      const as = {}; // authenticatorSelection
      const aa = request.body.opts.authenticatorSelection.authenticatorAttachment;
      const rr = request.body.opts.authenticatorSelection.requireResidentKey;
      const uv = request.body.opts.authenticatorSelection.userVerification;
      const cp = request.body.opts.attestation; // attestationConveyancePreference
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
        res.authenticatorSelection = as;
      }
      if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
        res.attestation = cp;
      }

      //Todo : 블록체인에 사용자 정보를 만들어서 넣는다.
      //DB에 해당 정보 기록
      db.get('users')
        .push(user)
        .write();
      ////////////////////////////////////////////////////

      response.json(res);

    } catch (e) {
      response.status(400).send({ error: e });
    }
});









router.get('/register',(request,response)=>{
  const username = request.body.username;
  const identifypart1 = 1//= request.body.user.idp1;
  const identifypart2  = 1//= request.body.user.idp2;
  //인증 과정이라고  생각

  if(username === undefined || identifypart1 === undefined || identifypart2 === undefined
    || !Number.isInteger(identifypart1) || !Number.isInteger(identifypart2) || identifypart1.length !== 6 
    || identifypart2.length !== 7){
 
    response.json({result:"no"});
    return;
  }

  //블록체인 -> 전체 조회를 통해서 가져옴
  //있는지를 확인하기 위함
  let user = db.get('users').value();

  //가져온 데이터를 통해서 동일한 주민번호가 있는지를 검사함.
  if(undefined !== user.find(element=>element.identify === (identifypart1 + "-" + identifypart2))){
    response.json({result:"isExist"});
    return;
  }

  //등록 절차 시작
  user = {
    username: username,
    //base64로 변환한 32자리의 랜덤 바이트를 id로 집어 넣는다.
    //이름은 특별한 의미가 없음. 그냥 base64로 암호화 한다는 것만 중요.
    id: coerceToBase64Url(crypto.randomBytes(32), 'user.id'),
    identify:identifypart1 + "-" + identifypart2,
    credentials: []
  }






});


/**
 * Check username, create a new account if it doesn't exist.
 * Set a `username` cookie.
 **/
router.post('/username', (req, res) => {
  const username = req.body.username;
  // Only check username, no need to check password as this is a mock
  //post form 요청에 username이 있는 경우에만 통과 시키고 잘못 넘어온 경우에는 잘못된 요청이라고 보냄
  if (!username) {
    res.status(400).send({ error: 'Bad request' });
    return;
  } else {
    //DB에서 등록 요청한 username이 있는지 확인을 한다.
    //블록체인 처리
    let user = db.get('users')
      .find({ username: username })
      .value();
    // If user entry is not created yet, create one
    //만약 DB상에 해당 username이 없는 경우
    //username과 id, credentials를 전달한다.
    if (!user) {
      user = {
        username: username,
        //base64로 변환한 32자리의 랜덤 바이트를 id로 집어 넣는다.
        //이름은 특별한 의미가 없음. 그냥 base64로 암호화 한다는 것만 중요.
        id: coerceToBase64Url(crypto.randomBytes(32), 'user.id'),
        credentials: []
      }
      //새로운 username을 user 객체로 만든뒤 db에 삽입한다.
      db.get('users')
        .push(user)
        .write();
    }
    // 브라우저에 username이라는 이름으로 쿠키를 생성하고 그 안에 username을 전달한다. 
    res.cookie('username', username);
    // If sign-in succeeded, redirect to `/home`.
    res.json(user);
  }
});

/**
 * Verifies user credential and let the user sign-in.
 * No preceding registration required.
 * This only checks if `username` is not empty string and ignores the password.
 **/
router.post('/password', (req, res) => {
  //비밀번호 없으면 짤 그러나 따로 처리 없기 떄문에 비밀번호도 무의미함.
  if (!req.body.password) {
    res.status(401).json({error: 'Enter at least one random letter.'});
    return;
  }
  //users라는 곳에서 쿠키에 저장되어있는 유저의 이름을 가져옴
  const user = db.get('users')
    .find({ username: req.cookies.username })
    .value();

    //유저가 없으면 짤
  if (!user) {
    res.status(401).json({error: 'Enter username first.'});
    return;
  }
  //db에서 id로 사용자 찾아서 비밀번호 일치여부 확인
  //id랑 지문이랑 일치하는지. 
  //블록체인.


  //로그인이 되었다는 의미로 cookie에 yes룰 표시해줌
  res.cookie('signed-in', 'yes');
  res.json(user);
});

router.get('/signout', (req, res) => {
  // Remove cookies
  res.clearCookie('username');
  res.clearCookie('signed-in');
  // Redirect to `/`
  res.redirect(302, '/');
});

/**
 * Returns a credential id
 * (This server only stores one key per username.)
 * Response format:
 * ```{
 *   username: String,
 *   credentials: [Credential]
 * }```

 Credential
 ```
 {
   credId: String,
   publicKey: String,
   aaguid: ??,
   prevCounter: Int
 };
 ```
 **/
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

router.get('/resetDB', (req, res) => {
  db.set('users', []).write();
  const users = db.get('users').value();
  res.json(users);
});

/**
 * Respond with required information to call navigator.credential.create()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     rp: {
       id: String,
       name: String
     },
     user: {
       displayName: String,
       id: String,
       name: String
     },
     publicKeyCredParams: [{  // @herrjemand
       type: 'public-key', alg: -7
     }],
     timeout: Number,
     challenge: String,
     excludeCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...],
     authenticatorSelection: {
       authenticatorAttachment: ('platform'|'cross-platform'),
       requireResidentKey: Boolean,
       userVerification: ('required'|'preferred'|'discouraged')
     },
     attestation: ('none'|'indirect'|'direct')
 * }```
 **/
router.post('/registerRequest', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.cookies.username;
  const user = db.get('users')
    .find({ username: username })
    .value();
  try {
    const response = await f2l.attestationOptions();
    response.user = {
      displayName: 'No name',
      id: user.id,
      name: user.username
    };
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    res.cookie('challenge', response.challenge);
    response.excludeCredentials = [];
    if (user.credentials.length > 0) {
      for (let cred of user.credentials) {
        response.excludeCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: ['internal']
        });
      }
    }
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

    res.json(response);
  } catch (e) {
    res.status(400).send({ error: e });
  }
});

/**
 * Register user credential.
 * Input format:
 * ```{
     id: String,
     type: 'public-key',
     rawId: String,
     response: {
       clientDataJSON: String,
       attestationObject: String,
       signature: String,
       userHandle: String
     }
 * }```
 **/
router.post('/registerResponse', csrfCheck, sessionCheck, async (req, res) => {
  const username = req.cookies.username;
  const challenge = coerceToArrayBuffer(req.cookies.challenge, 'challenge');
  const credId = req.body.id;
  const type = req.body.type;

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
      .find({ username: username })
      .value();

    user.credentials.push(credential);

    db.get('users')
      .find({ username: username })
      .assign(user)
      .write();

    res.clearCookie('challenge');

    // Respond with user info
    res.json(user);
  } catch (e) {
    res.clearCookie('challenge');
    res.status(400).send({ error: e.message });
  }
});

/**
 * Respond with required information to call navigator.credential.get()
 * Input is passed via `req.body` with similar format as output
 * Output format:
 * ```{
     challenge: String,
     userVerification: ('required'|'preferred'|'discouraged'),
     allowCredentials: [{
       id: String,
       type: 'public-key',
       transports: [('ble'|'nfc'|'usb'|'internal'), ...]
     }, ...]
 * }```
 **/
router.post('/signinRequest', csrfCheck, async (req, res) => {
  try {
    const user = db.get('users')
    .find({ username: req.body.username })
    .value();
   
    
    if (!user) {
      // Send empty response if user is not registered yet.
      res.json({error: 'User not found.'});
      return;
    }

    const credId = req.query.credId;
    console.log(credId);
    const response = await f2l.assertionOptions();

    // const response = {};
    response.userVerification = req.body.userVerification || 'preferred';
    response.challenge = coerceToBase64Url(response.challenge, 'challenge');
    res.cookie('challenge', response.challenge);

    response.allowCredentials = [];
    for (let cred of user.credentials) {
      console.log(cred);
      // When credId is not specified, or matches the one specified
      if (!credId || cred.credId == credId) {
        response.allowCredentials.push({
          id: cred.credId,
          type: 'public-key',
          transports: ['internal']
        });
      }
    }

    res.json(response);
  } catch (e) {
    res.status(400).json({ error: e });
  }
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
    res.clearCookie('challenge');
    res.status(400).json({ error: e });
  }
});

module.exports = router;
