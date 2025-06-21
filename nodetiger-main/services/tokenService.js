import jwt from "jsonwebtoken";
import config from '../config/constant.js';
import RefreshToken from "../models/oauth_refresh_token.js";

// Verify a refresh token
export async function verifyRefreshToken(refreshToken) {
    return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, config.jwt.refresh_token_secret, (error) => {
            if (error) {
                if (error.name === 'TokenExpiredError') {
                    reject({ status: 401, message: 'Refresh token has expired' });
                } else if (error.name === 'JsonWebTokenError') {
                    reject({ status: 401, message: 'Invalid refresh token' });
                } else {
                    reject({ status: 500, message: 'Internal server error' });
                }
            } else {
                resolve();
            }
        });
    });
}

// Generating a tokens
export async function generateTokens(payload) {
    const accessToken = jwt.sign(
        payload,
        config.jwt.access_token_secret,
        { expiresIn: config.jwt.access_token_exp }
    );

    const refreshToken = jwt.sign(
        payload,
        config.jwt.refresh_token_secret,
        { expiresIn: config.jwt.refresh_token_exp }
    );

    const token = await RefreshToken.findOne({ where: { userId: payload.userId } });
    if (token) {
        await token.destroy();
    }
    await RefreshToken.create({ userId: payload.userId, token: refreshToken });

    return { accessToken, refreshToken };
}