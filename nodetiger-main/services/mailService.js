import logger from '../config/logger.js';
// import sgMail from '@sendgrid/mail';
import config from '../config/constant.js';
import nodemailer from 'nodemailer';


// Sent a mail using sendgrid
// const sendEmail = async (email, subject, content) => {
//     try {
//         sgMail.setApiKey(config.smtp.password);

//         const msg = {
//             to: email,
//             from: config.smtp.sender_name,
//             subject: subject,
//             html: content
//         };

//         await sgMail.send(msg);
//     } catch (error) {
//         logger.error(`Error on sending an email: ${error}`);
//     }
// }


// Using NodeMailer to send the OTP email
const sendEmail = async (email, subject, content) => {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail', // service: 'smtp.gmail.com', // SMTP server
            // host: config.smtp.host,
            // port: config.smtp.port,
            // secure: config.smtp.secure, // true for 465, false for other ports
            auth: {
                user: config.smtp.sender_name,
                pass: config.smtp.password
            }
        });

        const mailOptions = {
            from: config.smtp.sender_name,
            to: email,
            subject: subject,
            html: content
        };

        const info = await transporter.sendMail(mailOptions);
        logger.info(`Email sent successfully: ${info.response}`);
        return { success: true, message: 'Email sent successfully', info };
    } catch (error) {
        logger.error(`Error on sending the email: ${error.message}`);
        return { success: false, message: 'Error on sending the email', error: error.message };
    }
};

export default sendEmail;
