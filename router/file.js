const express = require('express');
const jsZip = require('jszip');
const fs = require('fs');
const sequelize = require('./../models/index');
const router = express.Router();

router.all('*',(request, response, next)=>{
    //Fido 인증이 끝난경우 그에 대한 인증 코드를 부여하든 어떻게 하든 검사해야함. 아닌 경우 진입 금지
    if(request.session.auth === ""){
        next();
    }else{
        response.status(404).send("Invalid Access");
    }
})

router.get('/', async (request,response)=>{
    let transaction = null;
    try {
        transaction = await sequelize.transaction();

        //1. 토큰 검색 
        let token = request.body.token;
        if(token === undefined){
            response.status(404).send("Error");
            return;
        }

        //2. 토큰에 대한 정보를 찾기
        let papers = await sequelize.models.token.findAndCountAll({where:{token:token}, transaction});
        if(papers === undefined || papers.count === 0){
            response.status(404).send("Error");
            return;
        }

        let count = papers.count;
        let pathes = [];
        for(let i=0;i<count;++i){
            pathes.push(papers.rows[i].dataValues.path);
        }

        //3. 찾은 파일들 획득 - 시간이 오래 지난경우의 파일들도 제외해야함- 아직 없음
        let file = [];
        pathes.forEach(path => {
            file.push(fs.readFileSync(path,{encoding:"UTF-8"}));
        });

        //4. 찾은 파일들 압축 하여 한 파일로 만듦    
        var zip = new jsZip();
        for(let i=0;i<count;++i){
            zip.file( i + ".txt", fs.readFileSync(pathes[i],{encoding:"UTF-8"}));
        }
    
        let result = await zip.generateAsync({type:"nodebuffer"});
        await sequelize.models.token.destroy({where:{token:token}, transaction});
        response.setHeader("Content-Type","application/zip");
        response.send(result);
    } catch (error) {
        if(transaction){
            await transaction.rollback();
        }
        response.status(404).send("Error");
    }
});

module.exports = router;