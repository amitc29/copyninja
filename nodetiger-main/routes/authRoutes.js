import { Router } from 'express';
import passport from 'passport';

import * as OauthController from '../controllers/OAuthcontroller.js';

import '../config/strategies.js';


passport.serializeUser(function (user, cb) {
    cb(null, user);
});

passport.deserializeUser(function (obj, cb) {
    cb(null, obj);
});

const oauthRouter = Router();


// Oauth routes

// Authorising a details and get a auth code
oauthRouter.get("/authorize", OauthController.authorize);

// Get an access token based on auth code
oauthRouter.post("/token", OauthController.token);

// Protected routes access if authenticated
oauthRouter.get("/authenticate", OauthController.authenticate, OauthController.protectedRoute);

// Set a client
oauthRouter.post("/set_client", OauthController.createClient);



// Social logins routes

// Google
oauthRouter.get('/google',
    passport.authenticate('google', { scope: ['profile email'], accessType: 'offline', approvalPrompt: 'force' })
);

oauthRouter.get('/callback',
    passport.authenticate('google', {
        successRedirect: '/oauth/callback/success',
        failureRedirect: '/oauth/callback/failure'
    }
));


// Facebook
oauthRouter.get('/facebook',
    passport.authenticate('facebook')
);

oauthRouter.get('/facebook/callback',
    passport.authenticate('facebook', {
        successRedirect: '/oauth/callback/success',
        failureRedirect: '/oauth/callback/failure'
    })
);

// Apple
oauthRouter.get('/apple',
    passport.authenticate('apple', {
        scope: ['email', 'name'],
    })
);

oauthRouter.get('/apple/callback',
    passport.authenticate('apple', {
        successRedirect: '/oauth/callback/success',
        failureRedirect: '/oauth/callback/failure'
    })
);

// Success
oauthRouter.get('/callback/success', (req, res) => {
    return res.status(200).json({ status: 'success', user: req.user });
});

// Failure
oauthRouter.get('/callback/failure', (req, res) => {
    return res.status(400).json({ status: 'error', message: 'Internal server error'});
});

export default oauthRouter;
