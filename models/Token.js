import { Model, DataTypes } from 'sequelize';

class Token extends Model{}

let addTokenModel = (sequelize) => {
    Token.init({
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        token:{
            type:DataTypes.STRING,
            allowNull:0
        },
        type:{
            type:DataTypes.STRING,
            allowNull:0
        },
        path:{
            type:DataTypes.STRING,
            allowNull:0
        },
    },{
        sequelize,
        modelName:'token'
    });
}

export default addTokenModel;