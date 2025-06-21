import express from 'express';
import * as UserAuthController from "../controllers/UserAuthController.js";
import verifyToken from '../middleware/verifyTokens.js';

const apiRouter = express.Router();

// Registering a user
// apiRouter.post('/register', UserAuthController.register);

// Organization registration
apiRouter.post("/organization-registration", UserAuthController.organizationRegistration);

// For managing status of an organization from sportskeyz-backend service
apiRouter.post("/organizations/status", UserAuthController.setOrganizationStatus);

// Admin Login
apiRouter.post("/admin/login", UserAuthController.adminLogin);

// Password less registration
apiRouter.post("/register-passwordless", UserAuthController.passwordlessRegistration);

// Verify an OTP for registered user verification
apiRouter.post('/verify-otp', UserAuthController.verifyOTP);

// Sent an OTP for verifying a user
apiRouter.post("/send-otp", UserAuthController.sendOTP);

// Registering a user through portal
apiRouter.post("/portal-signup", UserAuthController.portalRegistration);

// Login a user through portal (for both dashboard and portal sign-in)
apiRouter.post("/portal-signin", UserAuthController.portalLogin);

// Generate a tokens if expired
apiRouter.post('/token', UserAuthController.tokens);

// If forgot a password
apiRouter.post('/forgot-password', UserAuthController.forgotPassword);

// Verify a magic link for recovering a password
apiRouter.get('/verify/:token', UserAuthController.verifyRecoverLink);

// Verify an OTP for recovering a password
apiRouter.post('/verify', UserAuthController.verifyRecoverOTP);

// For reset a password
apiRouter.post('/reset-password', verifyToken, UserAuthController.resetPassword);

// For Sign in
apiRouter.post('/login', UserAuthController.login);

// For Sign out
apiRouter.post("/logout", verifyToken, UserAuthController.logout);

// Sent an OTP through twilio
apiRouter.post("/send-twilio-otp", UserAuthController.sendTwilioOTP);

// Verify an OTP through twilio
apiRouter.post("/verify-twilio-otp", UserAuthController.verifyTwilioOTP);

// For deleting an account
apiRouter.delete("/delete-account/:spid", verifyToken, UserAuthController.deleteAccount);

export default apiRouter;