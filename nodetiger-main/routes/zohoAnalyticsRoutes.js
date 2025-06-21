
import config from '../config/constant.js';
import express from 'express';
const router = express();

const client_id = config.zoho.zoho_client_id;
const client_secret = config.zoho.zoho_client_secret;
const redirect_uri = config.zoho.zoho_redirect_uri;
const ZOHO_AUTH_URL = 'https://accounts.zoho.com/oauth/v2/auth';
const ZOHO_TOKEN_URL = 'https://accounts.zoho.com/oauth/v2/token';


router.get('/getcode', (req, res) => {
    const authURL = `${ZOHO_AUTH_URL}?response_type=code&client_id=${client_id}&redirect_uri=${redirect_uri}&scope=ZohoAnalytics.data.all&access_type=offline&prompt=consent`;
    res.redirect(authURL);
});

router.get('/callback', async (req, res) => {
    const { code } = req.query;
    if (!code) {
        return res.status(400).send('Authorization code not provided');
    }

    try {
        const response = await axios.post(ZOHO_TOKEN_URL, null, {
            params: {
                code,
                client_id: client_id,
                client_secret: client_secret,
                redirect_uri: redirect_uri,
                grant_type: 'authorization_code'
            }
        });

        const { access_token, refresh_token } = response.data;
        res.json({ access_token, refresh_token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


export default router;