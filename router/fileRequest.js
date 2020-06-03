import express, { response } from 'express';
import fs from 'fs';
import sequelize from './../models/index';
const router = express.Router();

router.all('*',(request, response, next)=>{
    //Fido 인증이 끝난경우 그에 대한 인증 코드를 부여하든 어떻게 하든 검사해야함. 아닌 경우 진입 금지
    if(request.session.auth === ""){
        next();
    }else{
        response.status(404).send("Invalid Access");
    }