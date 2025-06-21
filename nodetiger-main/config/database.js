import { Sequelize } from 'sequelize';
import config from './constant.js';

const sequelize = new Sequelize(
    config.database.name,
    config.database.username,
    config.database.password,
    {
        host: config.database.host,
        dialect: config.database.dialect,
        logging: false,  // Enables detailed SQL logs
        dialectOptions: {
            ssl: {
                require: true,
                rejectUnauthorized: false,
            },
        },
        logging: false
    }
);

const testConnection = async () => {
    try {
        await sequelize.authenticate();
        console.log('Connection has been established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
};

testConnection();

export default sequelize;