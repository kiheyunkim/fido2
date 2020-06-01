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


let register = async (opts, info)=>{
    if (!window.PublicKeyCredential) {
        throw 'WebAuthn not supported on this browser.';
    }

    const UVPAA = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    if (!UVPAA) {
        throw 'User Verifying Platform Authenticator not available.';
    }
    
    const options = await _fetch('/auth/registerRequest', {opts, info});
    
    options.user.id = base64url.decode(options.user.id);
    options.challenge = base64url.decode(options.challenge);
        
    const cred = await navigator.credentials.create({
        publicKey: options
    });
    console.log("hihihihihi");
    console.log(cred);
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

    console.log('ok');
    console.log(credential); 
    return await _fetch('/auth/registerResponse' , credential);
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
            }
          }
        let info = {
              id: id,
              username : username,
              idPart1 : idNum1,
              idPart2 : idNum2
          }

          console.log(info);
        register({opts, info});
    });
});
