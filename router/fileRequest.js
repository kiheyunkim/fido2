const express = require('express');
const sha256 = require('sha256');
const path = require('path');
const router = express.Router();
const sequelize = require('./../models/index.js');

router.all('*',(req,res,next)=>{
    if(!req.session.auth){
        res.status(404).send("forbidden");
    }else{
        next();
    }
});

let paperList = ['documentA','documentB','documentC','documentD']

router.get('/request', async (req,res)=>{
    let documentTypes = req.body.types;
    let requestId = req.session.signupId;
    let token = sha256(Date.toString() + documentTypes + Date.toString());

    documentTypes.array.forEach(element => {
        if(Number.isInteger(element) && 1 <= parseInt(element) && parseInt(element) <= 4){
            let requestPaperType = paperList[parseInt(element) - 1];
            //await sequelize.models.token.create({token:token, path:path.join(__dirname,"../file/",requestId,requestPaperType)});
        }
    });

    res.json({token:token});
});

module.exports = router;