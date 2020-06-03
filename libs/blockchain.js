const fs = require('fs');
const path = require('path');
    
const FabricCAServices = require('fabric-ca-client');
const { FileSystemWallet, X509WalletMixin, Gateway } = require('fabric-network');
    
const ccpPath = path.resolve(__dirname, '..' , 'basic_articles', 'connection-org1.json');
const ccpJSON = fs.readFileSync(ccpPath, 'utf8');
const ccp = JSON.parse(ccpJSON);
    
// Create a new CA client for interacting with the CA.
const caURL = ccp.certificateAuthorities['ca.example.com'].url;
const ca = new FabricCAServices(caURL);
    
// Create a new file system based wallet for managing identities.
const walletPath = path.join(process.cwd(), 'wallet');
const wallet = new FileSystemWallet(walletPath);
    
let init = async ()=>{
    try{
        // Check to see if we've already enrolled the admin user.
        const adminExists = await wallet.exists('admin');
        if (!adminExists) {
            // Enroll the admin user, and import the new identity into the wallet.
            const enrollment = await ca.enroll({ enrollmentID: 'admin', enrollmentSecret: 'adminpw' });
            const identity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
            wallet.import('admin', identity);
            console.log('Successfully enrolled admin user "admin" and impIDorted it into the wallet');
        }   
        
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            // Create a new gateway for connecting to our peer node.
            const gateway = new Gateway();
            await gateway.connect(ccp, { wallet, identity: 'admin', discovery: { enabled: false } });
    
            // Get the CA client object from the gateway for interacting with the CA.
            const ca = gateway.getClient().getCertificateAuthority();
            const adminIdentity = gateway.getCurrentIdentity();
    
            // Register the user, enroll the user, and import the new identity into the wallet.
            const secret = await ca.register({ affiliation: 'org1.department1', enrollmentID: 'user1', role: 'client' }, adminIdentity);
            const enrollment = await ca.enroll({ enrollmentID: 'user1', enrollmentSecret: secret });
            const userIdentity = X509WalletMixin.createIdentity('Org1MSP', enrollment.certificate, enrollment.key.toBytes());
            wallet.import('user1', userIdentity);
            console.log('Successfully registered and enrolled admin user "user1" and imported it into the wallet');
        }
    
        return true;
    }catch(e){
        return false;
    }
}

let getUserbyId = async (queryName) => {
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return {result:undefined};
        }
        console.log('hi1');
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
 
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
 
        // Get the contract from the network.
        const contract = network.getContract('mydata2');
 
        // Evaluate the specified transaction.   
        const result = await contract.evaluateTransaction('queryMydata', `${queryName}`);
        return {result:result.toString()};
    }catch(e){
        return {result:undefined};
    }
}


let checkUserExist = async (queryName) => {
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return false;
        }
 
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
 
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
 
        // Get the contract from the network.
        const contract = network.getContract('mydata2');
 
        // Evaluate the specified transaction.   
        const result = await contract.evaluateTransaction('queryMydata', `${queryName}`);
        console.log(`Transaction has been evaluated, result is: ${result.toString()} `);
        return true;
    }catch(e){
        return false;
    }
}

let getAllUser=async()=>{
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }
 
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
        // Get the contract from the network.
        const contract = network.getContract('mydata2');
        // Evaluate the specified transaction.   
        const resultDoc = await contract.evaluateTransaction('queryAlldocdatas');
        console.log(`Transaction has been evaluated, result is: ${resultDoc.toString()} `);
        return {result:resultDoc.toString()};

    }catch(e){
        return {result:undefined};
    }
}


let add_member = async (ID, Name, ID_Number, HashKey)=>{
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
        // Get the contract from the network.
        const contract = network.getContract('mydata2');
        // Evaluate the specified transaction.   
        await contract.submitTransaction('createMemberdata', `${ID}`, `${Name}`, `${ID_Number}`, `${HashKey}`);
        console.log(`Transaction has been evaluated, result is ok`);
        return true;

    }catch(e){
        return false
    }
}

let change_Public_Key = async (id,hashKey)=>{
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }
 
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
 
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
 
        // Get the contract from the network.
        const contract = network.getContract('mydata2');
 
        // Evaluate the specified transaction
        await contract.submitTransaction('changeOwnerKey', `${id}`,  `${hashKey}`);
        console.log(`Transaction has been evaluated, result is ok`);
        return true;
    }catch(e){
        return false;
    }  
}

let add_doc = async(id, incomeTax, localTax, businessRegistration, leaseAgreement)=>{
    try{ 
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }
 
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
 
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
 
        // Get the contract from the network.
        const contract = network.getContract('mydata3');
 
        // Evaluate the specified transaction.   
        await contract.submitTransaction('createDocdata', `${id}`, `${incomeTax}`, `${localTax}`, `${businessRegistration}`, `${leaseAgreement}`);
        console.log(`Transaction has been evaluated, result is ok`);
        return true;
    }catch(e){
        return false;
    }
}

let get_doc=async(queryName)=>{
    try{
        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }
 
        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });
 
        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');
 
        // Get the contract from the network.
        const contract = network.getContract('mydata3');
 
        // Evaluate the specified transaction.   
        const result = await contract.evaluateTransaction('queryMydata', `${queryName}`);
        console.log(`Transaction has been evaluated, result is: ${result.toString()} `);
        return {result:result.toString()};
    }catch(e){
        console.log(e);
        return {result:"fail"};
    }
}









module.exports = {init, getUserbyId, checkUserExist, getAllUser, add_member, change_Public_Key, change_Public_Key, add_doc, get_doc}