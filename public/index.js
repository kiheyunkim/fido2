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
    
    if (options.excludeCredentials) {
        for (let cred of options.excludeCredentials) {
            cred.id = base64url.decode(cred.id);
        }
    }
    
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