const _fetch = async (path, payload = '') => {
    const headers = {
      'X-Requested-With': 'XMLHttpRequest'
    };
    if (payload && !(payload instanceof FormData)) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(payload);
    }
    const res = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: headers,
      body: payload
    });
    console.log(res);

    if (res.status === 200) {
      // Server authentication succeeded
      return res.json();
    } else {
      // Server authentication failed
      const result = await res.json();
      throw result.error;
    }
  };


let register = async (opts)=>{
    if (!window.PublicKeyCredential) {
        throw 'WebAuthn not supported on this browser.';
    }

    const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!UVPAA) {
        throw 'User Verifying Platform Authenticator not available.';
    }
    
    const options = await _fetch('/auth/registerRequest', opts);
    console.log("hihihi");
    console.log(options);
    options.user.id = base64url.decode(options.user.id);
    options.challenge = base64url.decode(options.challenge);
        
    const cred = await navigator.credentials.create({
        publicKey: options
    });

    const credential = {};
    credential.id =     cred.id;
    credential.type =   cred.type;
    credential.rawId =  base64url.encode(cred.rawId);

    if (cred.response) {
    const clientDataJSON =
        base64url.encode(cred.response.clientDataJSON);
    const attestationObject =
        base64url.encode(cred.response.attestationObject);
    credential.response = {
            clientDataJSON,
            attestationObject
        };
    }
    
    localStorage.setItem(`credId`, credential.id);

    return await _fetch('/auth/registerResponse' , credential);
}

let signin = async (opts) =>{
  if (!window.PublicKeyCredential) {
    console.info('WebAuthn not supported on this browser.');
    return Promise.resolve(null)
  } 

  const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  if (!UVPAA) {
    console.info('User Verifying Platform Authenticator not available.');
    return Promise.resolve(null);
  }

  let url = '/auth/signinRequest';
  //const credId = localStorage.getItem(`credId`);
  //if (credId) {
  //  url += `?credId=${encodeURIComponent(credId)}`;
  //}

  const options = await _fetch(url, opts);
  console.log(options);
  if (options.allowCredentials.length === 0) {
    console.info('No registered credentials found.');
    return Promise.resolve(null);
  }

  options.challenge = base64url.decode(options.challenge);

  for (let cred of options.allowCredentials) {
    cred.id = base64url.decode(cred.id);
  }

  const cred = await navigator.credentials.get({
    publicKey: options
  });

  const credential = {};
  credential.id =     cred.id;
  credential.type =   cred.type;
  credential.rawId =  base64url.encode(cred.rawId);

  if (cred.response) {
    const clientDataJSON =
      base64url.encode(cred.response.clientDataJSON);
    const authenticatorData =
      base64url.encode(cred.response.authenticatorData);
    const signature =
      base64url.encode(cred.response.signature);
    const userHandle =
      base64url.encode(cred.response.userHandle);
    credential.response = {
      clientDataJSON,
      authenticatorData,
      signature,
      userHandle
    };

    console.log('hi');
    return await _fetch(`/auth/signinResponse`, credential);
  }
}

$(document).ready(()=>{
    $('#send').click(()=>{
        let id = $("#id").val();
        let username = $("#username").val();
        let idNum1 = $("#idNum1").val();
        let idNum2 = $("#idNum2").val(); 

        let opts = {
            attestation: 'none',
            authenticatorSelection: {
              authenticatorAttachment: 'platform',
              userVerification: 'required'
            },
            id: id,
            username : username,
            idPart1 : idNum1,
            idPart2 : idNum2
        }

        register(opts);
    });

    $('#send2').click(()=>{
      let id = $("#signin").val();

      signin({id}).then(user => {
        console.log(user);
      if (user) {
        location.href = '/home';
      }
        }).catch(e => {
          console.error(e);
          alert('Authentication failed. Use password to sign-in.');
        });
    });
});



