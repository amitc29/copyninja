// import twilio from 'twilio';
import config from '../config/constant.js';
import logger from '../config/logger.js';
import sendEmail from '../services/mailService.js';
import https from 'https';

let sharedOTP = null;

// const id = config.twilio.account_id;
// const token = config.twilio.auth_token;
// const client = twilio(id, token);

/**
 * Generate an OTP
 * @returns
 */
export function generateOTP() {
    // Generate a 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000);
    sharedOTP = otp;

    // Set OTP expiration time (5 minutes from now)
    const otpExpiresAt = new Date(Date.now() + 5 * 60 * 1000);

    return { otp, otpExpiresAt };
}

/**
 * Sent an OTP on phone
 * @param {*} phone
 */
export async function sendOTPPhoneConfirmation(phone) {

    // await client.messages.create({
    //         body: `${config.twilio.template} : ${sharedOTP}`,
    //         from: config.twilio.service_id,
    //         to: `+91${phone}`
    //     });

    return new Promise((resolve, reject) => {
        const options = {
            method: 'POST',
            hostname: 'control.msg91.com',
            path: '/api/v5/flow',
            headers: {
                authkey: `${config.msg91.auth_key}`,
                accept: 'application/json',
                'content-type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let chunks = [];

            res.on('data', (chunk) => {
                chunks.push(chunk);
            });

            res.on('end', () => {
                const body = Buffer.concat(chunks).toString();
                logger.info(`MSG91 Response: ${body}`);
                resolve(body);
            });
        });

        req.on('error', (error) => {
            logger.error(`MSG91 Error: ${error.message}`);
            reject(error);
        });

        const payload = JSON.stringify({
            template_id: `${config.msg91.template_id}`,
            short_url: "0",
            recipients: [
                {
                    mobiles: `91${phone}`,
                    var: `${sharedOTP}`,
                }
            ]
        });

        req.write(payload);
        req.end();
    });
}

/**
 * Sent an OTP on email
 * @param {*} email
 * @param {*} subject
 * @param {*} content
 */
export async function sendOTPEmailConfirmation(email, subject, content) {
    await sendEmail(email, subject, content);
}

/**
 * Sent an OTP through twilio
 * @param {*} phone
 */
// export async function sendOTPThroughTwilio(phone) {
//     await client.verify.v2
//         .services(config.twilio.otp_service_id)
//         .verifications.create({
//             to: `+91${phone}`,
//             channel: "sms"
//         });
// }

/**
 * Verify an OTP through twilio
 * @param {*} phone
 */
// export async function verifyOTPThroughTwilio(phone, otp) {
//     const response = await client.verify.v2
//         .services(config.twilio.otp_service_id)
//         .verificationChecks.create({
//             to: `+91${phone}`,
//             code: otp
//         });

//     return response;
// }