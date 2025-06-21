import express from 'express';
import https from 'https';
import fs from 'fs';

import client from 'prom-client';
import responseTime from 'response-time';

import rateLimit from 'express-rate-limit';
import cors from 'cors';
import helmet from 'helmet';
import cookieparser from 'cookie-parser';

import sequelize from './config/database.js';
import logger from './config/logger.js';
import config from './config/constant.js';

import authRoutes from './routes/authRoutes.js';
import apiRoutes from './routes/apiRoutes.js';
import zohoRoutes from './routes/zohoAnalyticsRoutes.js';

import session from 'express-session';
import passport from 'passport';

import bodyParser from 'body-parser';

import swaggerUI from 'swagger-ui-express';
import YAML from 'yamljs';

const specs = YAML.load('./openapi.yaml');

const app = express();

app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(specs));

const collectDefaultMetrics = client.collectDefaultMetrics;
collectDefaultMetrics({ register: client.register });

const reqResTime = new client.Histogram({
    name: "http_express_req_res_time",
    help: "This tell us how much time is taken by request and response",
    labelNames: ["method", "route", "status_code"],
    buckets: [1, 50, 100, 200, 400, 500, 800, 1000, 2000]
});

const totalReqCounter = new client.Counter({
    name: "total_req",
    help: "it tell us total requests count"
});

app.use(responseTime((req, res, time) => {
    totalReqCounter.inc();

    reqResTime.labels({
        method: req.method,
        route: req.url,
        status_code: res.statusCode
    }).observe(time);
}));

app.get('/metrics', async (req, res) => {
    res.setHeader("Content-Type", client.register.contentType);
    const metrics = await client.register.metrics();

    return res.end(metrics);
});

app.use(session({
    secret: config.session.secret,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(cookieparser());

app.use(helmet());

app.use(express.json({ limit: "4mb" }));

app.use(express.urlencoded({ extended: true, limit: "4mb" }));

app.use(cors());

app.use(bodyParser.urlencoded({ extended: true }));

(async () => {
    try {
        await sequelize.sync();
        logger.info(`Database connection established and models synced.`);
    } catch (error) {
        logger.error(`Error synchronizing models with the database: ${error}`);
    }
})();

const apiRequestLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // in 1 minute
    max: 30 // 30 requests
});

app.use(apiRequestLimiter);

app.use('/zoho', zohoRoutes)
app.use('/', apiRoutes);
app.use('/oauth', authRoutes);

(async () => {
    try {
        const PORT = config.port || 5011;

        app.listen(PORT, () => {
            logger.info(`Server running on port ${PORT}`);
            console.log(`Running on port http://localhost:${PORT}`);
        });

        // const options = {
        //     key: fs.readFileSync('key.pem'), // Path to private key
        //     cert: fs.readFileSync('cert.pem') // Path to certificate
        // };
        
        // const PORT = config.port || 5011;
        // https.createServer(options, app).listen(PORT, () => {
        //     logger.info(`HTTPS Server running on port ${PORT}`);
        //     console.log(`Secure Server running at https://localhost:${PORT}`);
        // });
    } catch (error) {
        logger.error(`Server connection error : ${error}`);
    }
})();