import jwt from "jsonwebtoken";
import config from '../config/constant.js';
import logger from '../config/logger.js';

const verifyToken = (req, res, next) => {
    if (!req.headers.authorization) {
        return res.status(401).json({ message: 'Authorization header missing' });
    }

    const token = req.headers.authorization.split(' ')[1];
    // const cookieToken = req.cookies['access-token'];

    if (!token) {
        return res.status(401).json({ message: 'Token not provided' });
    }

    // if (token !== cookieToken) {
    //     return res.status(401).json({ message: 'Invalid access token' });
    // }

    jwt.verify(token, config.jwt.access_token_secret, (error, decoded) => {
        if (error) {
            if (error.name === 'TokenExpiredError') {
                logger.error("Access token has expired");

                return res.status(401).json({ status: 'error', message: 'Access token has expired' });
            } else if (error.name === 'JsonWebTokenError') {
                logger.error("Invalid access token");

                return res.status(401).json({ status: 'error', message: 'Invalid access token' });
            } else {
                logger.error(`Internal server error: ${error}`);

                return res.status(500).json({ status: 'error', message: 'Internal server error' });
            }
        } else {
            req.userId = decoded.userId;
            next();
        }
    });
};

export default verifyToken;