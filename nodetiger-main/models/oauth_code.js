import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const OAuthAuthorizationCode = sequelize.define('oauth_authorization_code', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    }, 
    authorizationCode: {
        type: DataTypes.STRING
    },
    expiresAt: {
        type: DataTypes.DATE
    },
    redirectUri: {
        type: DataTypes.STRING
    },
    scope: {
        type: DataTypes.STRING
    },
    clientId: {
        type: DataTypes.STRING
    },
    userId: {
        type: DataTypes.STRING
    },
    codeChallenge: {
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

export default OAuthAuthorizationCode;
