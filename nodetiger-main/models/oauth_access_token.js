import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const OAuthAccessToken = sequelize.define('oauth_access_token', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    }, 
    accessToken: {
      	type: DataTypes.STRING
    },
    accessTokenExpiresAt: {
      	type: DataTypes.DATE
    },
    scope: {
      	type: DataTypes.STRING
    },
    clientId: {
      	type: DataTypes.STRING
    },
    userId: {
      	type: DataTypes.STRING
    }
    // userId: {
    //     type: DataTypes.INTEGER,
    //     references: {
    //         model: User,
    //         key: 'id'
    //     }
    // },
});

export default OAuthAccessToken;
