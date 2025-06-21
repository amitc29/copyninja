import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const User = sequelize.define('user', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    spid : {
        type: DataTypes.STRING,
        unique: true
    },
    type: {
        type: DataTypes.STRING
    },
    provider_id: {
        type: DataTypes.STRING
    },
    is_approved: {
        type: DataTypes.TINYINT,
        defaultValue: 0
    },
    provider: {
        type: DataTypes.STRING
    },
    email: {
        type: DataTypes.STRING,
        unique: true
    },
    emailConfirmedAt: {
        type: DataTypes.DATE
    },
    phone: {
        type: DataTypes.STRING,
        unique: true
    },
    phoneConfirmedAt: {
        type: DataTypes.DATE
    },
    name: {
        type: DataTypes.STRING
    },
    password: {
        type: DataTypes.STRING
    },
    isSSOUser: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    active: {
        type: DataTypes.BOOLEAN,
        defaultValue: false
    },
    otp: { 
        type: DataTypes.STRING
    },
    otpExpiresAt: { 
        type: DataTypes.DATE
    },
	deletedAt: {
        type: DataTypes.DATE
    }
});

export default User;