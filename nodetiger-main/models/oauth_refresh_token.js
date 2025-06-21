import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const OAuthRefreshToken = sequelize.define('oauth_refresh_token', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    }, 
    refreshToken: {
        type: DataTypes.STRING
    },
    refreshTokenExpiresAt: {
        type: DataTypes.DATE
    },
    scope: {
        type: DataTypes.STRING
    },
    clientId: {
        type: DataTypes.STRING
    },
    userId: DataTypes.STRING,
    // userId: {
    //     type: DataTypes.INTEGER,
    //     references: {
    //         model: User,
    //         key: 'id'
    //     }
    // },
    token: {
        type: DataTypes.STRING,
        // allowNull: false
    }
});

export default OAuthRefreshToken;