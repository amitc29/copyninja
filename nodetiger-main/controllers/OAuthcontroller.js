import OAuth2Server from "oauth2-server";
import { Request, Response } from 'oauth2-server';
import jwt from "jsonwebtoken";

import * as oAuth2Models from "../services/oauth2Service.js";
import logger from '../config/logger.js';
import config from '../config/constant.js';

import OAuthClient from '../models/oauth_client.js';
import User from '../models/user.js';

import crypto from "crypto";
import OAuthAuthorizationCode from "../models/oauth_code.js";

import clientValidation from '../validations/clientValidation.js';

const server = new OAuth2Server({
    model: oAuth2Models,
    // grants: ['authorization_code', 'refresh_token'],
    // accessTokenLifetime: 60 * 60 * 1,
    // refreshTokenLifetime: 60 * 60 * 24,
    // authCodeLifetime: 120
    // allowEmptyState: true,
    // allowExtendedTokenAttributes: true
})

export async function authorize(req, res) {
    const request = new Request(req);
    const response = new Response(res);

    return server
        .authorize(request, response, {
            authenticateHandler: {
                handle: async () => {
                    const { client_id, scope, code_challenge, code_challenge_method } = request.query || {};

                    if (code_challenge_method !== 's256') throw new Error("Invalid code challange method");

                    if (!client_id) throw new Error("Client ID not found");

                    try {
                        const client = await OAuthClient.findOne({
                            where: { clientId: client_id },
                        });

                        if (!client) throw new Error("Client not found");

                        const requestedScopes = scope ? scope.split(' ') : [];

                        const allowedScopes = client.scopes || [];

                        const validScopes = requestedScopes.filter(s => allowedScopes.includes(s));
                        if (validScopes.length === 0) {
                            throw new Error("Requested scopes are not valid for this client.");
                        }

                        const { userId } = req.auth || {};

                        if (!client.userId && !userId) return null;

                        const user = await User.findOne({
                            where: {
                                ...(client.userId && { id: client.userId }),
                                ...(userId && { clerkId: userId }),
                            },
                        });

                        if (!user) throw new Error("User not found");

                        return {
                            id: user.id,
                            scope: validScopes,
                            codeChallenge: code_challenge
                        };
                    } catch (error) {
                        throw new Error(error.message);
                    }
                },
            },
        })
        .then((result) => {
            return res.json(result);
        })
        .catch((err) => {
            logger.error(`Error on authorising a user: ${err}`);
            return res
                .status(err.code || 500)
                .json(err instanceof Error ? { error: err.message } : err);
        });
}

export async function token(req, res) {
    try {
        if (req.body.code) {
            const codeVerifier = req.body.code_verifier;
    
            const codeEntry = await OAuthAuthorizationCode.findOne({
                where: { authorizationCode: req.body.code }
            });
            if (codeEntry) {
                if (!compareCodeVerifierAndChallenge(codeVerifier, codeEntry.codeChallenge)) {
                    throw new Error('Invalid code verifier');
                }
            }
        }

        const request = new Request(req);
        const response = new Response(res);

        const result = await server
        .token(request, response, { alwaysIssueNewRefreshToken: false });
        
        const userId = result.user?.id;
        const clientId = req.body.client_id || result.client?.id;

        // Check if 'openid' scope is requested
        const requestedScopes = result.scope ? result.scope.split(' ') : null;
        const includeIdToken = requestedScopes ? requestedScopes.includes('openid') : null;

        if (includeIdToken) {
            const secretKey = config.jwt.access_token_secret;
            const user = await User.findOne({ where: { id: userId } });

            const idToken = jwt.sign({
                sub: userId,
                iss: config.url,
                aud: clientId,
                iat: Math.floor(Date.now() / 1000),
                exp: 3600,
                email: user.email,
                phone: user.phone
            }, secretKey);

            result.id_token = idToken;
        }

        return res.json(result);
    } catch (err) {
        logger.error(`Error on getting an access token: ${err}`);
        return res
            .status(err.code || 500)
            .json(err instanceof Error ? { error: err.message } : err);
    }
}

export async function authenticate(req, res, next) {
    try {
        const request = new Request(req);
        const response = new Response(res);

        const data = await server.authenticate(request, response);
        req.auth = { userId: data?.user?.id, sessionType: "oauth2" };
        next();
    } catch (err) {
        logger.error(`Error on authenticating a user: ${err}`);
        return res
            .status(err.code || 500)
            .json(err instanceof Error ? { error: err.message } : err);
    }
}

export async function protectedRoute(req, res) {    
    try {
        const { userId } = req.auth || {};
        if (!userId) throw new Error("User not found");

        const user = await User.findOne({ where: { id: userId } });

        if (!user) throw new Error("User not found");

        return res.json({ id: user.id, email: user.email, phone: user.phone });
    } catch (error) {
        logger.error(`Error on authorising a user: ${err}`);
        throw new Error(error.message);
    }
}

export async function createClient(req, res) {
    try {
        const { error } = clientValidation.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: 'error', messages: errorMessages });
        }

        const { clientId, clientSecret, redirectUri, grants, scopes } = req.body;

        const client = await OAuthClient.findOne({
            where: { clientId: clientId }
        });

        if (client) {
            return res.status(400).json({ status: "error", error: "Client already exists!" });
        }

        const createdClient = await OAuthClient.create({
            clientId: clientId,
            clientSecret: clientSecret,
            callbackUrl: redirectUri,
            grants: grants,
            scopes: scopes 
        });

        return res.status(201).json({status: "success", createdClient});
    } catch (err) {
        logger.error(`Error on creating a client: ${err}`);
        return res.status(500).json({ status: "error", err: "Internal server error" });
    }
}

function compareCodeVerifierAndChallenge(codeVerifier, storedCodeChallenge) {
    const generatedCodeChallenge = base64UrlEncode(crypto.createHash('sha256').update(codeVerifier).digest());
    return generatedCodeChallenge === storedCodeChallenge;
}

function base64UrlEncode(str) {
    return Buffer.from(str).toString('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}