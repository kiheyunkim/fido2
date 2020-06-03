const addTokenModel = require('./Token');
const {Sequelize} = require('sequelize');
const config = require(__dirname + '/../config/config.json');

let sequelize = new Sequelize(config.database, config.username, config.password, config);

addTokenModel(sequelize);

module.exports = sequelize;