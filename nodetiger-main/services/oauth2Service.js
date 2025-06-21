import OAuthAccessToken from '../models/oauth_access_token.js';
import OAuthRefreshToken from '../models/oauth_refresh_token.js';
import OAuthClient from '../models/oauth_client.js';
import OAuthAuthorizationCode from '../models/oauth_code.js';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import User from '../models/user.js';
import Sequelize from 'sequelize';
import jwt from 'jsonwebtoken';
import config from '../config/constant.js';

export async function getClient(clientId, clientSecret) {
    const client = await OAuthClient.findOne({
        where: { clientId, ...(clientSecret && { clientSecret }) }
    });

    if (!client) throw new Error("Client not found");

    return {
        id: client.clientId,
        grants: client.grants,
        redirectUris: [client.callbackUrl]
    };
}

export async function saveAuthorizationCode(code, client, user) {
    const authorizationCode = {
        authorizationCode: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        scope: code.scope,
        clientId: client.id,
        codeChallenge: user.codeChallenge,
        userId: user.id
    };
    await OAuthAuthorizationCode.create({
        _id: uuidv4(),
        ...authorizationCode
    });

    const responseAuthorizationCode = { ...authorizationCode };
    delete responseAuthorizationCode.codeChallenge;

    return responseAuthorizationCode;
}

export async function getAuthorizationCode(authorizationCode) {
    const code = await OAuthAuthorizationCode.findOne({
        where: { authorizationCode }
    });
    if (!code) throw new Error("Authorization code not found");

    return {
        code: code.authorizationCode,
        expiresAt: code.expiresAt,
        redirectUri: code.redirectUri,
        scope: code.scope,
        client: { id: code.clientId },
        user: { id: code.userId }
    };
}

export async function revokeAuthorizationCode({ code }) {
    const deletedCount = await OAuthAuthorizationCode.destroy({
        where: { authorizationCode: code }
    });
    return deletedCount === 1;
}

export async function revokeToken({ refreshToken }) {
    const deletedCount = await OAuthAccessToken.destroy({
        where: { refreshToken }
    });
    return deletedCount === 1;
}

export async function generateAccessToken(client, user, scope, callback) {
    const accessToken = jwt.sign(
        { 
            userId: user.id,
        },
        config.jwt.access_token_secret,
        { expiresIn: config.jwt.access_token_exp }
    );

    // Call the callback function with the generated access token
    if (callback) {
        callback(null, accessToken);
    }

    return accessToken;
}

export async function generateRefreshToken(client, user, scope, callback) {
    const refreshToken = jwt.sign(
        { userId: user.id },
        config.jwt.refresh_token_secret,
        { expiresIn: config.jwt.refresh_token_exp }
    );

    // Call the callback function with the generated refresh token
    if (callback) {
        callback(null, refreshToken);
    }

    return refreshToken;
}

export async function saveToken(token, client, user) {
    const createdAccessToken = await OAuthAccessToken.create({
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        scope: token.scope,
        clientId: client.id,
        userId: user.id
    });

    let createdRefreshToken;
    if (token.refreshToken) {
        createdRefreshToken = await OAuthRefreshToken.create({
            refreshToken: token.refreshToken,
            refreshTokenExpiresAt: new Date(new Date().getTime() + 24 * 60 * 60 * 1000),
            scope: token.scope,
            clientId: client.id,
            userId: user.id
        });
    }

    return {
        accessToken: createdAccessToken.accessToken,
        token_type:'bearer',
        accessTokenExpiresAt: createdAccessToken.accessTokenExpiresAt,
        refreshToken: createdRefreshToken ? createdRefreshToken.refreshToken : null,
        refreshTokenExpiresAt: createdRefreshToken ? createdRefreshToken.refreshTokenExpiresAt : null,
        scope: token.scope,
        client: { id: client.id },
        user: { id: user.id }
    };
}

export async function getAccessToken(accessToken) {
    const token = await OAuthAccessToken.findOne({
        where: { accessToken }
    });
    if (!token) throw new Error("Access token not found");

    return {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt,
        scope: token.scope,
        client: { id: token.clientId },
        user: { id: token.userId }
    };
}

export async function getUser(username, password) {
    let emailOrPhone = username;
    try {
        const user = await User.findOne({
            where: {
                [Sequelize.Op.or]: [
                    { email: emailOrPhone },
                    { phone: emailOrPhone }
                ]
            }
        });

        if (!user) {
            throw new Error("User not found");
        }

        const isMatch = bcrypt.compareSync(password, user.password);
        if (isMatch) {
            return user;
        } else {
            throw new Error("Password not matched");
        }
    } catch (error) {
        throw new Error(error.message);
    }
}

export async function getRefreshToken(refreshToken) {
    const token = await OAuthRefreshToken.findOne({
        where: { refreshToken }
    });
    if (!token) throw new Error("Refresh token not found");

    return {
        refreshToken: token.refreshToken,
        refreshTokenExpiresAt: token.refreshTokenExpiresAt, // never expires
        scope: token.scope,
        client: { id: token.clientId },
        user: { id: token.userId }
    };
}