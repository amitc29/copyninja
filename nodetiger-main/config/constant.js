import dotenv from 'dotenv';

dotenv.config();

const config = {
    url: process.env.NODETIGER_APP_URL,
    sportkeyz_url: process.env.SPORTKEYZ_APP_URL,
    port: process.env.NODETIGER_PORT,
    database: {
        host: process.env.NODETIGER_DB_HOST,
        name: process.env.NODETIGER_DB_DATABASE,
        username: process.env.NODETIGER_DB_USERNAME,
        password: process.env.NODETIGER_DB_PASSWORD,
        dialect: process.env.NODETIGER_DB_DIALECT
    },
    jwt: {
        access_token_secret: process.env.NODETIGER_JWT_ACCESS_TOKEN_SECRET,
        access_token_exp: process.env.NODETIGER_JWT_ACCESS_TOKEN_EXP,
        refresh_token_secret: process.env.NODETIGER_JWT_REFRESH_TOKEN_SECRET,
        refresh_token_exp: process.env.NODETIGER_JWT_REFRESH_TOKEN_EXP
    },
    twilio: {
        account_id: process.env.NODETIGER_SMS_TWILIO_ACCOUNT_SID,
        auth_token: process.env.NODETIGER_SMS_TWILIO_AUTH_TOKEN,
        service_id: process.env.NODETIGER_SMS_TWILIO_MESSAGE_SERVICE_SID,
        otp_service_id: process.env.NODETIGER_SMS_TWILIO_SERVICE_SID,
        template: process.env.NODETIGER_SMS_TEMPLATE
    },
    smtp: {
        password: process.env.NODETIGER_SMTP_PASS,
        sender_name: process.env.NODETIGER_SMTP_SENDER_NAME,
        host: process.env.NODETIGER_SMTP_HOST, //add host, port and secure (for 465 tru and others false) details in the env file
        port: process.env.NODETIGER_SMTP_PORT,
        secure: process.env.NODETIGER_SMTP_SECURE
    },
    cookie: {
        access_token_duration: process.env.NODETIGER_ACCESS_TOKEN_COOKIE_DURATION,
        refresh_token_duration: process.env.NODETIGER_REFRESH_TOKEN_COOKIE_DURATION
    },
    google: {
        client_id: process.env.NODETIGER_EXTERNAL_GOOGLE_CLIENT_ID,
        client_secret: process.env.NODETIGER_EXTERNAL_GOOGLE_SECRET,
        redirect_uri: process.env.NODETIGER_EXTERNAL_GOOGLE_REDIRECT_URI
    },
    facebook: {
        client_id: process.env.NODETIGER_EXTERNAL_FACEBOOK_CLIENT_ID,
        client_secret: process.env.NODETIGER_EXTERNAL_FACEBOOK_SECRET,
        redirect_uri: process.env.NODETIGER_EXTERNAL_FACEBOOK_REDIRECT_URI
    },
    apple: {
        client_id: process.env.NODETIGER_EXTERNAL_APPLE_CLIENT_ID,
        client_secret: process.env.NODETIGER_EXTERNAL_APPLE_SECRET,
        redirect_uri: process.env.NODETIGER_EXTERNAL_APPLE_REDIRECT_URI
    },
    session: {
        secret: process.env.NODETIGER_SESSION_SECRET
    },
    grafana: {
        loki_url: process.env.GRAFANA_LOKI_URL
    },
    zoho:{
        zoho_client_id: process.env.ZOHO_CLIENT_ID,
        zoho_client_secret: process.env.ZOHO_CLIENT_SECRET,
        zoho_refresh_token: process.env.ZOHO_REFRESH_TOKEN,
        zoho_redirect_uri: process.env.ZOHO_REDIRECT_URI
    },
    msg91: {
        auth_key: process.env.NODETIGER_SMS_MSG91_AUTH_KEY,
        template_id: process.env.NODETIGER_SMS_MSG91_TEMPLATEID
    },
};

export default config;
