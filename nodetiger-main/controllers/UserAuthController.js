import crypto from 'crypto';
import Sequelize from 'sequelize';
import fetch from "node-fetch";

import logger from '../config/logger.js';
import config from '../config/constant.js';

import UserType from "../utils/userType.js";

import User from "../models/user.js";
import RefreshToken from "../models/oauth_refresh_token.js";
import ResetPassword from "../models/reset_password.js";

import * as passwordService from '../services/passwordService.js';
import * as otpService from '../services/otpService.js';
import * as tokenService from '../services/tokenService.js';
import * as cookieService from '../services/cookieService.js';
import * as spidService from '../services/spidService.js';

import signupValidation from '../validations/signupValidation.js';
import signinValidation from '../validations/signinValidation.js';
import generateTokenValidation from '../validations/generateTokenValidation.js';
import passwordlessSignupValidation from "../validations/passwordlessSignupValidation.js";
import organizationSignupValidation from "../validations/organizationSignupValidation.js";

/**
 * Register a user
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function register(req, res) {
    try {
        const { error } = signupValidation.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: 'error', messages: errorMessages });
        }

        const { email, phone, password } = req.body;

        const { otp, otpExpiresAt } = otpService.generateOTP();

        const encryptedPassword = await passwordService.generatePassword(password);

        if (phone) {
            const phoneExist = await User.findOne({ where: { phone: phone } });
            if (phoneExist) {
                return res.status(404).json({ status: 'error', message: `Phone number already taken.` });
            }

            const user = {
                phone,
                password: encryptedPassword,
                spid: spidService.generateSPIDNumber(),
                otp,
                otpExpiresAt
            };
            await User.create(user);

            otpService.sendOTPPhoneConfirmation(phone);

            return res.status(201).json({ status: 'success', message: `We have sent an OTP on your phone number for verification.` });
        } else {
            const emailExist = await User.findOne({ where: { email: email } });
            if (emailExist) {
                return res.status(404).json({ status: 'error', message: `Email already taken.` });
            }

            const user = {
                email,
                password: encryptedPassword,
                spid: spidService.generateSPIDNumber(),
                otp,
                otpExpiresAt
            };
            await User.create(user);

            otpService.sendOTPEmailConfirmation(
                user.email,
                'Your Magic Link',
                `<p><b>Magic Link</b></p><p>Enter Below OTP to login:</p><p>code: <b>${otp}</b></p>`
            );

            return res.status(201).json({ status: 'success', message: `We have sent an OTP on your email for verification.` });
        }
    } catch (error) {
        logger.error(`Error on creating a user: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Register a user without password
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function passwordlessRegistration(req, res) {
    try {
        const { error } = passwordlessSignupValidation.validate(req.body, {
            abortEarly: false
        });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: "error", messages: errorMessages });
        }

        const { email, phone } = req.body;

        const { otp, otpExpiresAt } = otpService.generateOTP();

        if (phone) {
            const phoneExist = await User.findOne({ where: { phone: phone } });
            if (phoneExist) {
                return res
                    .status(404)
                    .json({ status: "error", message: `Phone number already taken.` });
            }

            const user = {
                phone,
                spid: spidService.generateSPIDNumber(),
                otp,
                otpExpiresAt
            };
            await User.create(user);

            otpService.sendOTPPhoneConfirmation(phone);

            return res.status(201).json({
                status: "success",
                message: "We have sent an OTP on your phone number for verification."
            });
        } else {
            const emailExist = await User.findOne({ where: { email: email } });
            if (emailExist) {
                return res
                    .status(404)
                    .json({ status: "error", message: 'Email already taken.' });
            }

            const user = {
                email,
                spid: spidService.generateSPIDNumber(),
                otp,
                otpExpiresAt
            };
            await User.create(user);

            otpService.sendOTPEmailConfirmation(
                user.email,
                "Your Sign up OTP",
                `<p>Enter Below OTP to sign up:</p><p>code: <b>${otp}</b></p>`
            );

            return res.status(201).json({
                status: "success",
                message: `We have sent an OTP on your email for verification.`
            });
        }
    } catch (error) {
        logger.error(`Error on registering a user: ${error}`);

        return res
            .status(500)
            .json({ status: "error", error: "Internal server error" });
    }
}

/**
 * Verify an OTP for signup
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function verifyOTP(req, res) {
    try {
        const { email, phone, otp, type } = req.body;

        if (!email && !phone) {
            return res.status(400).json({ status: 'error', message: 'Either email or phone must be provided' });
        }

        const query = email ? { email } : { phone };
        const user = await User.findOne({ where: query });

        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ status: 'error', message: 'Invalid OTP' });
        }

        if (user.otpExpiresAt < Date.now()) {
            user.otp = null;
            user.otpExpiresAt = null;
            await user.save();

            return res.status(400).json({ status: 'error', message: 'OTP has been expired' });
        }

        user.active = true;
        user.otp = null;
        user.otpExpiresAt = null;
        await user.save();

        if (type && type == "org_registration") {
            const admin = await User.findOne({ where: { type: 'admin' } });

            otpService.sendOTPEmailConfirmation(
                admin.email,
                "New Organization Sign up",
                `<p>Hey Admin,</p> <p>The new organization is sign up with the email: <b>${user.email}</b></p>`
            );

            return res
                .status(200)
                .json({
                    status: "success",
                    message:
                        "Your account is created. please wait for admin approval.",
                });
        }

        const tokens = await tokenService.generateTokens({ userId: user.id });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: 'success',
            message: 'OTP successfully verified.',
            spid: user.spid,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresIn: '1 hour',
            tokenType: 'Bearer'
        });
    } catch (error) {
        logger.error(`Error on verifying an OTP: ${error}`);

        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Verifying an OTP for recovering a password
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function verifyRecoverOTP(req, res) {
    try {
        const { email, phone, otp } = req.body;

        if (!email && !phone) {
            return res.status(400).json({ status: 'error', message: 'Either email or phone must be provided' });
        }

        const query = email ? { email } : { phone };
        const user = await User.findOne({ where: query });

        if (!user) {
            return res.status(400).json({ status: 'error', message: 'User not found' });
        }

        const resetPassword = await ResetPassword.findOne({ where: query });

        if (resetPassword.otp !== otp) {
            return res.status(400).json({ status: 'error', message: 'Invalid OTP' });
        }

        if (resetPassword.otpExpiresAt < Date.now()) {
            await ResetPassword.destroy({
                where: { id: resetPassword.id }
            });
            return res.status(400).json({ status: 'error', message: 'OTP has been expired' });
        }

        await ResetPassword.destroy({
            where: { id: resetPassword.id }
        });

        const tokens = await tokenService.generateTokens({ userId: user.id });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: 'success',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        logger.error(`Error on verifying an OTP: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Verifying an email link for recovering a password
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function verifyRecoverLink(req, res) {
    try {
        const resetToken = req.params.token;

        const resetPassword = await ResetPassword.findOne({ where: { recoveryToken: resetToken } });

        if (!resetPassword) {
            return res.status(400).json({ status: 'error', message: 'Invalid link' });
        }

        if (resetPassword.recoverySentAt < Date.now()) {
            await ResetPassword.destroy({
                where: { id: resetPassword.id }
            });

            return res.status(400).json({ status: 'error', message: 'Link has been expired' });
        }

        const user = await User.findOne({
            where: {
                [Sequelize.Op.or]: [
                    { email: resetPassword.email },
                    { phone: resetPassword.phone }
                ]
            }
        });

        await ResetPassword.destroy({
            where: { id: resetPassword.id }
        });

        const tokens = await tokenService.generateTokens({ userId: user.id });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: 'success',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        logger.error(`Error on verifying an email link: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Forgot a password
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function forgotPassword(req, res) {
    try {
        const { email, phone } = req.body;

        if (!email && !phone) {
            return res.status(400).json({ status: 'error', message: 'Either email or phone must be provided' });
        }

        const query = email ? { email } : { phone };
        const user = await User.findOne({ where: query });

        if (!user) {
            return res.status(400).json({ status: 'error', message: 'User not found' });
        }

        const { otp, otpExpiresAt } = otpService.generateOTP();

        if (phone) {
            const resetPassword = {
                phone,
                otp,
                otpExpiresAt
            };
            await ResetPassword.create(resetPassword);

            otpService.sendOTPPhoneConfirmation(phone);

            return res.status(200).json({});
        } else {
            const resetToken = crypto.randomBytes(32).toString('hex');

            const resetPassword = {
                email,
                otp,
                otpExpiresAt,
                recoveryToken: resetToken,
                recoverySentAt: new Date(Date.now() + 5 * 60 * 1000)
            };
            await ResetPassword.create(resetPassword);

            const resetLink = `${config.url}/verify/${resetToken}`;

            otpService.sendOTPEmailConfirmation(
                user.email,
                'Reset Your Password',
                `<h2>Reset password</h2>
                <p>Follow this link to reset the password for your user:</p>
                <p><a href="${resetLink}">Reset password</a></p>
                <p>Alternatively, enter the code: ${otp}</p>`
            );

            return res.status(200).json({});
        }
    } catch (error) {
        logger.error(`Error on forgot password: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Reset a password
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function resetPassword(req, res) {
    try {
        const { email, phone, password } = req.body;

        if (!email && !phone) {
            return res.status(400).json({ status: 'error', message: 'Either email or phone must be provided' });
        }

        const query = email ? { email } : { phone };
        const user = await User.findOne({ where: query });

        if (!user) {
            return res.status(400).json({ status: 'error', message: 'User not found' });
        }

        const encryptedPassword = await passwordService.generatePassword(password);
        user.password = encryptedPassword;
        await user.save();

        return res.status(200).json({ status: 'success', message: 'Password reset successfully' });
    } catch (error) {
        logger.error(`Error on reseting a password: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Send an OTP
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function sendOTP(req, res) {
    try {
        const { error } = passwordlessSignupValidation.validate(req.body, {
            abortEarly: false
        });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);

            logger.error(`Validation error on sending an OTP: ${errorMessages}`);

            return res.status(400).json({ status: "error", messages: errorMessages });
        }

        const { email, phone } = req.body;

        const query = email ? { email } : { phone };
        const user = await findOrCreateUser(query, phone);

        if (phone) {
            otpService.sendOTPPhoneConfirmation(phone);
        } else {
            otpService.sendOTPEmailConfirmation(
                user.email,
                'OTP',
                `<p>code: <b>${user.otp}</b></p>`
            );
        }

        return res.status(201).json({
            status: "success",
            message: `We have sent an OTP on your ${phone ? 'phone' : 'email'} for verification.`
        });
    } catch (error) {
        logger.error(`Error on sending an OTP: ${error}`);

        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Login a user through portal
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function portalLogin(req, res) {
    try {
        const { error } = passwordlessSignupValidation.validate(req.body, {
            abortEarly: false
        });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: "error", messages: errorMessages });
        }

        const { email, phone, type } = req.body;

        const query = email ? { email } : { phone };
        const user = await User.findOne({ where: query });

        if (!user) {
            return res.status(404).json({ status: 'error', message: 'User not found' });
        }

        if (user.type && user.type != type) {
            return res.status(401).json({ status: 'error', message: 'Unauthorized' });
        }

        if (type == 'organization') {
            if (user.is_approved == 0) {
                return res.status(200).json({ status: 'error', message: 'Please wait for admin approval' });
            }
            if (user.is_approved == 2) {
                return res.status(200).json({ status: 'error', message: 'Invalid credentials' });
            }
        }

        const { otp, otpExpiresAt } = otpService.generateOTP();

        user.otp = otp;
        user.otpExpiresAt = otpExpiresAt;
        await user.save();

        if (phone) {
            otpService.sendOTPPhoneConfirmation(phone);
        } else {
            otpService.sendOTPEmailConfirmation(
                user.email,
                'OTP',
                `<p>code: <b>${user.otp}</b></p>`
            );
        }

        return res.status(201).json({
            status: "success",
            message: `We have sent an OTP on your ${phone ? 'phone' : 'email'} for verification.`
        });
    } catch (error) {
        logger.error(`Error on login a user through portal: ${error}`);

        return res
            .status(500)
            .json({ status: "error", error: "Internal server error" });
    }
}

/**
 * Register a user through portal
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function portalRegistration(req, res) {
    try {
        const { error } = passwordlessSignupValidation.validate(req.body, {
            abortEarly: false
        });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: "error", messages: errorMessages });
        }

        const { email, phone } = req.body;

        const { otp, otpExpiresAt } = otpService.generateOTP();

        if (phone) {
            const phoneExist = await User.findOne({ where: { phone: phone } });
            if (phoneExist) {
                return res
                    .status(404)
                    .json({ status: "error", message: `Phone number already taken.` });
            }

            const user = {
                phone,
                spid: spidService.generateSPIDNumber(),
                type: UserType.User,
                otp,
                otpExpiresAt
            };
            await User.create(user);

            otpService.sendOTPPhoneConfirmation(phone);

            return res.status(201).json({
                status: "success",
                message: "We have sent an OTP on your phone number for verification."
            });
        } else {
            const emailExist = await User.findOne({ where: { email: email } });
            if (emailExist) {
                return res
                    .status(404)
                    .json({ status: "error", message: 'Email already taken.' });
            }

            const user = {
                email,
                spid: spidService.generateSPIDNumber(),
                type: UserType.User,
                otp,
                otpExpiresAt
            };
            await User.create(user);
            otpService.sendOTPEmailConfirmation(
                user.email,
                "Your Sign up OTP",
                `<p>Enter Below OTP to sign up:</p><p>code: <b>${otp}</b></p>`
            );

            return res.status(201).json({
                status: "success",
                message: `We have sent an OTP on your email for verification.`
            });
        }
    } catch (error) {
        logger.error(`Error on registering a user through portal: ${error}`);

        return res
            .status(500)
            .json({ status: "error", error: "Internal server error" });
    }
}

async function findOrCreateUser(query) {
    const { otp, otpExpiresAt } = otpService.generateOTP();
    
    const [user, created] = await User.findOrCreate({
        where: query,
        defaults: {
            spid: spidService.generateSPIDNumber(),
            type: UserType.User,
            otp: otp,
            otpExpiresAt: otpExpiresAt,
        },
    });

    if (!created) {
        user.type = UserType.User;
        user.otp = otp;
        user.otpExpiresAt = otpExpiresAt;
        await user.save();
    }

    return user;
}

/**
 * Sign in an user into system
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function login(req, res) {
    try {
        const { error } = signinValidation.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: 'error', messages: errorMessages });
        }

        const { email, phone, password } = req.body;

        const user = await User.findOne({ where: email ? { email } : { phone } });

        if (!user) {
            return res.status(404).json({ status: 'error', message: `Invalid credentials.` });
        }

        if (!user.active) {
            return res.status(404).json({ status: 'error', message: `Please verify an account first.` });
        }

        const verifiedPassword = await passwordService.compareHashAndPassword(password, user.password);

        if (!verifiedPassword) {
            return res.status(401).json({ status: 'error', message: "Invalid credentials" });
        }

        const tokens = await tokenService.generateTokens({ userId: user.id });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: 'success',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            message: "Logged in successfully"
        });
    } catch (error) {
        logger.error(`Error on login: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Generate a tokens
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function tokens(req, res) {
    try {
        const { error } = generateTokenValidation.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: 'error', messages: errorMessages });
        }

        const { grant_type, email, phone, password, refresh_token } = req.body;

        let userId = '';

        if (grant_type === 'password') {
            const user = await User.findOne({
                where: {
                    [email ? 'email' : 'phone']: email || phone
                }
            });

            if (!user || !(await passwordService.compareHashAndPassword(password, user.password))) {
                return res.status(404).json({ status: 'error', message: `Invalid credentials.` });
            }

            userId = user.id;
        } else {
            const refreshToken = await RefreshToken.findOne({ where: { token: refresh_token } });

            if (!refreshToken) {
                return res.status(404).json({ status: 'error', message: `Invalid token.` });
            }

            // const cookieToken = req.cookies['refresh-token'];

            // if (refresh_token !== cookieToken) {
            //     return res.status(401).json({ message: 'Invalid refresh token' });
            // }

            await tokenService.verifyRefreshToken(refreshToken.token);

            const user = await User.findOne({ where: { id: refreshToken.userId } });
            userId = user.id;
        }

        const tokens = await tokenService.generateTokens({ userId });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: 'success',
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        });
    } catch (error) {
        logger.error(`Error on creating a tokens: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Sign out an user from system
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function logout(req, res) {
    try {
        // const refreshCookie = req.cookies['refresh-token'];

        // if (!refreshCookie) {
        //     return res.status(401).json({ status: 'error', message: 'Unauthorized' });
        // }

        await RefreshToken.destroy({
            // where: { token: refreshCookie }
            where: { userId: req.userId }
        });

        cookieService.clearCookieTokens(res);

        return res.status(200).json({
            status: 'success',
            message: 'Log out successfully'
        });
    } catch (error) {
        logger.error(`Error in logout: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Send OTP through twilio
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function sendTwilioOTP(req, res) {
    try {
        const { phone } = req.body;

        otpService.sendOTPThroughTwilio(phone);

        return res.status(201).json({ status: 'success', message: `We have sent an OTP on your phone number for verification.` });
    } catch (error) {
        logger.error(`Error on sending an OTP through twilio: ${error}`);

        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Verify OTP through twilio
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function verifyTwilioOTP(req, res) {
    try {
        const { phone, otp } = req.body;

        const response = await otpService.verifyOTPThroughTwilio(phone, otp);

        return res.status(200).json({ response });
    } catch (error) {
        logger.error(`Error on verifying an OTP through twilio: ${error}`);

        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Delete a user account
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function deleteAccount(req, res) {
    try {
        const { spid } = req.params;

        const user = await User.findOne({ where: { spid: spid } });

        if (!user) {
            return res.status(404).json({
                status: "error",
                message: "User not found"
            });
        }

        await User.destroy({
            where: { spid: spid }
        });

        cookieService.clearCookieTokens(res);

        return res.status(200).json({
            status: 'success',
            message: 'Account successfully deleted'
        });
    } catch (error) {
        logger.error(`Error on deleting an account: ${error}`);

        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Register an organization
 * @param {*} req
 * @param {*} res
 * @returns
 */
export async function organizationRegistration(req, res) {
    try {
        const { error } = organizationSignupValidation.validate(req.body, { abortEarly: false });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: 'error', messages: errorMessages });
        }

        const { name, email, contactNumber, type, level, headQuarter, logo } = req.body;

        const contactExist = await User.findOne({ where: { phone: contactNumber } });
        if (contactExist) {
            return res.status(404).json({ status: 'error', message: `Contact number already taken.` });
        }
        
        const emailExist = await User.findOne({ where: { email: email } });
        if (emailExist) {
            return res.status(404).json({ status: 'error', message: `Email already taken.` });
        }
        
        const headers = {
            "Content-Type": `application/json`
        };
        
        let body = JSON.stringify({
            orgName: name
        });
        
        const orgExistResponse = await fetch(
            `${config.sportkeyz_url}/organizations/is-exist`,
            {
                method: "POST",
                headers,
                body
            }
        );
        
        const exist = await orgExistResponse.json();
        
        if (exist.status === "error") {
            return res
            .status(404)
            .json({
                status: "error",
                message: exist.message,
            });
        }
        

        const user = {
            email,
            phone: contactNumber,
            // spid: spidService.generateSPIDNumber(type, level),
            spid: spidService.generateSPIDNumber(type, type === 'Sport Organisation' ? level : null),
            type: UserType.Organization
        };

        await User.create(user);

        const url = `${config.sportkeyz_url}/organizations/create`;

        body = JSON.stringify({
            spid: user.spid,
            name: name,
            email: email,
            contactNumber: contactNumber,
            type: type,
            level: level,
            headQuarter: headQuarter,
            logo: logo
        });

        const response = await fetch(url, {
            method: "POST",
            headers,
            body
        });

        await response.json();

        const { otp, otpExpiresAt } = otpService.generateOTP();

        const userDetail = await User.findOne({ where: { email: user.email } });
        userDetail.otp = otp;
        userDetail.otpExpiresAt = otpExpiresAt;
        await userDetail.save();

        otpService.sendOTPEmailConfirmation(
            userDetail.email,
            'OTP',
            `<p>code: <b>${userDetail.otp}</b></p>`
        );

        console.log("spid number: ", userDetail.spid);
        return res.status(201).json({
            status: "success",
            message: `We have sent an OTP on your email for verification.`
        });

        // if (responseData.status == 'success') {
        //     otpService.sendOTPEmailConfirmation(
        //         user.email,
        //         'Account created',
        //         `<p>Hey <b>${name}</b>,</p><p>Your account is created</p>` //TODO: need to add portal link here for redirection
        //     );

        //     return res.status(201).json({ status: 'success', message: `Account successfully created.` });
        // } else {
        //     return res.status(500).json({ status: 'error', message: `Something went wrong.` });
        // }
    } catch (error) {
        logger.error(`Error on creating a user: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * For managing status of an organization
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function setOrganizationStatus(req, res) {
    try {
        const { spid, is_approved } = req.body;

        const organization = await User.findOne({ where: { spid: spid } });
        organization.is_approved = is_approved;
        await organization.save();

        return res.status(201).json({
            status: "success"
        });
    } catch (error) {
        logger.error(`Error on setting up an organization status: ${error}`);
        return res.status(500).json({ status: 'error', error: 'Internal server error' });
    }
}

/**
 * Sign in an admin into system
 * @param {*} req 
 * @param {*} res 
 * @returns 
 */
export async function adminLogin(req, res) {
    try {
        const { error } = signinValidation.validate(req.body, {
            abortEarly: false,
        });
        if (error) {
            const errorMessages = error.details.map((detail) => detail.message);
            return res.status(400).json({ status: "error", messages: errorMessages });
        }

        const { email, phone, password } = req.body;

        const user = await User.findOne({ where: email ? { email } : { phone } });

        if (!user) {
            return res
                .status(404)
                .json({ status: "error", message: `Invalid credentials.` });
        }

        const verifiedPassword = await passwordService.compareHashAndPassword(
            password,
            user.password
        );

        if (!verifiedPassword) {
            return res
                .status(401)
                .json({ status: "error", message: "Invalid credentials" });
        }

        const tokens = await tokenService.generateTokens({ userId: user.id });

        cookieService.setCookieTokens(res, tokens);

        return res.status(200).json({
            status: "success",
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            message: "Logged in successfully",
        });
    } catch (error) {
        logger.error(`Error on login: ${error}`);
        return res
            .status(500)
            .json({ status: "error", error: "Internal server error" });
    }
}