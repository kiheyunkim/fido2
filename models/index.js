import addTokenModel from './Token';
import { Sequelize } from 'sequelize';
const config = require(__dirname + '/../config/config.json');

const sequelize = new Sequelize(config.database, config.username, config.password, config);

addTokenModel(sequelize);


export default sequelize;