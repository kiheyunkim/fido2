const fs = require('fs');
const path = require('path');
const sha256 = require('sha256');
const blockchain = require('./../libs/blockchain');

let generate = async (id, name)=>{
    if(fs.existsSync(path.join(__dirname,id))){
        return false;
    }
    fs.mkdirSync(path.join(__dirname,id));

    let titleTemp = "id: " +id +" name: "+name+ "  ";
    let title = "";
    let documentPrototypeA = fs.readFileSync(path.join(__dirname,"file/prototype/documentA"),{encoding:"utf-8"});
    title = titleTemp + "서류A\n" + documentPrototypeA;
    let documentAHash = title;

    fs.writeFileSync(path.join(__dirname,id,"documentA"),title,{encoding:"utf-8"});

    let documentPrototypeB = fs.readFileSync(path.join(__dirname,"file/prototype/documentB"),{encoding:"utf-8"});
    title = titleTemp+ "서류B\n" + documentPrototypeB;
    let documentBHash = title;

    fs.writeFileSync(path.join(__dirname,id,"documentB"),title,{encoding:"utf-8"});

    let documentPrototypeC = fs.readFileSync(path.join(__dirname,"file/prototype/documentC"),{encoding:"utf-8"});
    title = titleTemp + "서류C\n" +  documentPrototypeC;
    let documentCHash = title;

    fs.writeFileSync(path.join(__dirname,id,"documentC"),title,{encoding:"utf-8"});

    let documentPrototypeD = fs.readFileSync(path.join(__dirname,"file/prototype/documentD"),{encoding:"utf-8"});
    title = titleTemp + "서류D\n" +  documentPrototypeD;
    let documentDHash = title;

    fs.writeFileSync(path.join(__dirname,id,"documentD"),title,{encoding:"utf-8"});

    await blockchain.add_doc(id,sha256(documentAHash),sha256(documentBHash),sha256(documentCHash),sha256(documentDHash))

    return true;
}



module.exports = {generate}