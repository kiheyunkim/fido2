import { Router } from 'express';
const router = Router();
import jsZip from 'jszip';
import { readFileSync } from 'fs';
import sequelize from './../models/index';

router.get('/', async (request,response)=>{
    console.log('in file');

    console.log(request.query);
    let transaction = null;
    try {
        transaction = await sequelize.transaction();

        //1. 토큰 검색 
        let token = request.query.token;
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