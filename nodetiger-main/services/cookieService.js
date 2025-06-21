import config from '../config/constant.js';

// Storing a tokens into a cookie
export function setCookieTokens(res, tokens) {
    res.cookie('access-token', tokens.accessToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: config.cookie.access_token_duration
    });

    res.cookie('refresh-token', tokens.refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: config.cookie.refresh_token_duration
    });
}

// Clearing a tokens cookies
export function clearCookieTokens(res) {
    res.cookie('access-token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        expires: new Date(0),
        maxAge: 0
    });

    res.cookie('refresh-token', '', {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        expires: new Date(0),
        maxAge: 0
    });
}