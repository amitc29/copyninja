import passport from 'passport';

import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import { Strategy as AppleStrategy } from 'passport-apple';

import User from '../models/user.js';

import config from './constant.js';
import logger from './logger.js';


// Google strategy
passport.use(new GoogleStrategy({
    clientID: config.google.client_id,
    clientSecret: config.google.client_secret,
    callbackURL: config.google.redirect_uri,
    scope: ['profile', 'email'],
}, async (accessToken, refreshToken, profile, done) => {
    await createOrFindUser(profile, done);
}));


// Facebook strategy
passport.use(new FacebookStrategy({
    clientID: config.facebook.client_id,
    clientSecret: config.facebook.client_secret,
    callbackURL: config.facebook.redirect_uri
}, async function (accessToken, refreshToken, profile, done) {
    await createOrFindUser(profile, done);
}));


// Apple strategy
passport.use(new AppleStrategy({
    clientID: 'YOUR_APPLE_CLIENT_ID',
    teamID: config.apple.team_id,
    callbackURL: config.apple.redirect_uri,
    keyID: config.apple.key_id,
    privateKeyLocation: config.apple.private_key_path,
}, async (accessToken, refreshToken, decodedIdToken, profile, done) => {
    await createOrFindUser(profile, done);
}));


async function createOrFindUser(profile, done) {
    try {
        let existingUser = await User.findOne({ where: { provider_id: profile.id } });
        // const existingUser = await User.findOne({ where: { email: profile.emails[0].value } });

        if (existingUser) {
            existingUser.email = profile.emails ? profile.emails[0].value : existingUser.email;
            existingUser.name = profile.displayName;

            await existingUser.save();
        } else {
            await User.create({
                email: profile.emails ? profile.emails[0].value : null,
                name: profile.displayName,
                provider_id: profile.id,
                provider: profile.provider
            });
        }
        return done(null, profile );
    } catch (error) {
        logger.error(`Error on signin : ${error}`);
        return done(error, false);
    }
}