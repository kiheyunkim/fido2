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

// init project
const express = require('express');
const cookieParser = require('cookie-parser');
const hbs = require('hbs');
const auth = require('./libs/auth');
const fileRouter = require('./router/file').default;
const fileRequestRouter = require('./router/fileRequest').default;
const app = express();
const fs = require('fs');
const session = require('express-session');
const https = require('https');
app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.set('views', './views');
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static('public'));
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));



app.use((req, res, next) => {
  if (req.get('x-forwarded-proto') &&
     (req.get('x-forwarded-proto')).split(',')[0] !== 'https') {
    return res.redirect(301, `https://${process.env.HOSTNAME}`);
  }
  req.schema = 'https';
  next();
});

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, res) => {
  // Check cookie
  //쿠키에 이미 이름이 있으면 재인증 페이지로 이동
  if (req.cookies.username) {
    // If user is signed in, redirect to `/reauth`.
    res.redirect(307, '/reauth');
    return;
  }
  // If user is not signed in, show `index.html` with id/password form.
  res.render('index.html');
});

app.get('/home', (req, res) => {
  if (!req.cookies.username ||
      req.cookies['signed-in'] != 'yes') {
    // If user is not signed in, redirect to `/`.
    res.redirect(307, '/');
    return;
  }
  // `home.html` shows sign-out link
  res.render('home.html', {username: req.cookies.username});
});

app.get('/reauth', (req, res) => {
  const username = req.cookies.username;
  //쿠키가 없으면 루트로 이동하고 있으면 reauth.html을 뿌린다. 
  //username에는 cookie에 등록된 것과 같은 username을 준다
  if (!username) {
    res.redirect(302, '/');
    return;
  }
  // Show `reauth.html`.
  // User is supposed to enter a password (which will be ignored)
  // Make XHR POST to `/signin`
  res.render('reauth.html', {username: username});
});

app.get('/.well-known/assetlinks.json', (req, res) => {
  const assetlinks = [];
  const relation = [
    'delegate_permission/common.handle_all_urls',
    'delegate_permission/common.get_login_creds'
  ];
  if (process.env.HOSTNAME) {
    assetlinks.push({
      relation: relation,
      target: {
        namespace: 'web',
        site: `https://${process.env.HOSTNAME}`
      }
    });
  }
  if (process.env.ANDROID_PACKAGENAME && process.env.ANDROID_SHA256HASH) {
    assetlinks.push({
      relation: relation,
      target: {
        namespace: 'android_app',
        package_name: process.env.ANDROID_PACKAGENAME,
        sha256_cert_fingerprints: [process.env.ANDROID_SHA256HASH]
      }
    });
  }
  res.json(assetlinks);
});

app.use('/auth', auth);
app.use('/file',fileRouter);
app.use('/fileRequest',fileRequestRouter);

// listen for req :)
const port = process.env.GLITCH_DEBUGGER ? null : 443;

var options = {   
	ca: fs.readFileSync(__dirname +'/keyfile/ca_bundle.crt'),
  key: fs.readFileSync(__dirname +'/keyfile/private.key'),
  cert: fs.readFileSync(__dirname +'/keyfile/certificate.crt'),
};


https.createServer(options,app).listen(port,() => {
  console.log('Your app is listening on port ' + port);
});
