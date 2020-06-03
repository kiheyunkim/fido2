const fs = require('fs');
const path = require('path');

let generate = (id, name)=>{
    if(fs.existsSync(path.join(__dirname,id))){
        return false;
    }
    fs.mkdirSync(path.join(__dirname,id));

    let titleTemp = "id: " +id +" name: "+name+ "\n";
    let title = "";
    let documentPrototypeA = fs.readFileSync(path.join(__dirname,"prototype/documentA"),{encoding:"utf-8"});
    title = titleTemp + documentPrototypeA;

    fs.writeFileSync(path.join(__dirname,id,"documentA"),title,{encoding:"utf-8"});

    let documentPrototypeB = fs.readFileSync(path.join(__dirname,"prototype/documentB"),{encoding:"utf-8"});
    title = titleTemp + documentPrototypeB;

    fs.writeFileSync(path.join(__dirname,id,"documentB"),title,{encoding:"utf-8"});

    let documentPrototypeC = fs.readFileSync(path.join(__dirname,"prototype/documentC"),{encoding:"utf-8"});
    title = titleTemp + documentPrototypeC;

    fs.writeFileSync(path.join(__dirname,id,"documentC"),title,{encoding:"utf-8"});

    let documentPrototypeD = fs.readFileSync(path.join(__dirname,"prototype/documentD"),{encoding:"utf-8"});
    title = titleTemp + documentPrototypeD;

    fs.writeFileSync(path.join(__dirname,id,"documentD"),title,{encoding:"utf-8"});

    return true;
}

module.exports = {generate}