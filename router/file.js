import { Router } from 'express';
import jsZip from 'jszip';
import { readFileSync } from 'fs';
import sequelize from './../models/index';
const router = Router();

router.get('/', async (request,response)=>{
    let transaction = null;
    try {
        transaction = await sequelize.transaction();

        //1. 토큰 검색 
        let token = 'cfccba25be812d506b7a9a68d6774b630cf8ffa3f18d4180361511d06cb64e9c'//request.body.token;
        if(token === undefined){
            response.status(404).send("Error");
            return;
        }

        //2. 토큰에 대한 정보를 찾기
        let papers = await sequelize.models.token.findAndCountAll({where:{token:token}, transaction});
        console.log(papers.count);
        console.log(papers);
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
            file.push(readFileSync(path,{encoding:"UTF-8"}));
        });

        //4. 찾은 파일들 압축 하여 한 파일로 만듦    
        var zip = new jsZip();
        for(let i=0;i<count;++i){
            zip.file( i + ".txt", readFileSync(pathes[i],{encoding:"UTF-8"}));
        }
    
        let result = await zip.generateAsync({type:"nodebuffer"});
        await sequelize.models.token.destroy({where:{token:token}, transaction});
        response.setHeader("Content-Type","application/zip");
        response.send(result);
    } catch (error) {
        console.log(error);
        if(transaction){
            await transaction.rollback();
        }
        response.status(404).send("Error");
    }
});

export default router;