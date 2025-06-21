import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const ResetPassword = sequelize.define('reset_password', {
    id: {
        type: DataTypes.UUID,
        defaultValue: DataTypes.UUIDV4,
        primaryKey: true
    },
    email: {
        type: DataTypes.STRING
    },
    phone: {
        type: DataTypes.STRING
    },
    otp: {
        type: DataTypes.STRING
    },
    otpExpiresAt: {
        type: DataTypes.DATE
    },
    recoveryToken: {
        type: DataTypes.STRING
    },
    recoverySentAt: {
        type: DataTypes.DATE
    }
});

export default ResetPassword;