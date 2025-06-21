import winston from 'winston';
import { createLogger, transports } from "winston";
import LokiTransport from "winston-loki";

import config from "./constant.js";

const fileTransport = new winston.transports.File({
    filename: 'application.log',
    format: winston.format.combine(
        winston.format.timestamp({ format: 'DD-MM-YYYY HH:mm:ss' }),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    )
});

const lokiTransport = new LokiTransport({
    labels: {
        appName: "Auth (sportskeyz)"
    },
    host: config.grafana.loki_url
});

const logger = winston.createLogger({
    format: winston.format.json(),
    transports: [fileTransport, lokiTransport]
});

export default logger;
