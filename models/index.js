import Sequelize from 'sequelize';
import {addTokenModel} from './Token';

const config = require(__dirname + '/../config/config.json');

let sequelize = sequelize = new Sequelize(config.database, config.username, config.password, config);

addTokenModel(sequelize);

export default sequelize;