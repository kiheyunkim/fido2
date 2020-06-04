import { Router } from 'express';
const router = Router();
const sha256 = require('sha256');
const path = require('path');
const sequelize = require('./../models/index').default;

/*  router.all('*',(req,res,next)=>{
    if(!req.session.auth){
        res.status(404).send("forbidden");
    }else{
        next();
    }
});
 */
let paperList = ['documentA','documentB','documentC','documentD']

router.post('/request', async (req,res)=>{
    console.log('request file');
    let documentTypes = [1,2,3,4];
    let requestId = req.session.authId;

    let token = sha256((new Date) + documentTypes +(new Date));

    let length = documentTypes.length;
    for(let i=0;i<length;++i){
        let element = documentTypes[i];
        if(Number.isInteger(element) && 1 <= parseInt(element) && parseInt(element) <= 4){
            let requestPaperType = paperList[parseInt(element) - 1];
            await sequelize.models.token.create({token:token, path:path.join(__dirname,"../file/", 'email2', requestPaperType)});
        }
    }
    console.log(token);

    res.json({token});
});

export default router;