// src/utils/logger.ts

import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';

import { sanitizePayload } from './loggerUtils';
import asyncLocalStorage from './requestContext';

dotenv.config();

const logToFile = process.env.LOG_TO_FILE === 'true';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const logPath = path.join(__dirname, '../../logs');

// Ambil dari AsyncLocalStorage
const getRequestContext = () => {
    const store = asyncLocalStorage.getStore();
    return {
        payload: store?.payload ?? null,
        requestId: store?.requestId ?? 'N/A',
    };
};

// Format payload agar lebih rapi di terminal
const formatPrettyPayload = (payloadStr: string): string => {
    try {
        const obj = JSON.parse(payloadStr);
        const entries = Object.entries(obj)
            .map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
            .join(', ');
        return `{ ${entries} }`;
    } catch {
        return payloadStr;
    }
};

// Format warna ke terminal
const consoleFormat = winston.format.combine(
    winston.format.colorize({ all: true }),
    winston.format.timestamp({ format: 'HH:mm:ss' }),
    winston.format.printf(({ level, message, timestamp }) => {
        const { requestId, payload } = getRequestContext();
        const sanitized = sanitizePayload(payload);

        const payloadInfo = sanitized ? ` [payload: ${formatPrettyPayload(sanitized)}]` : '';

        return `[${timestamp}] [${level}] [req:${requestId}]${payloadInfo}: ${message}`;
    }),
);

// Transports
const transports: winston.transport[] = [new winston.transports.Console({ format: consoleFormat })];

if (logToFile) {
    transports.push(
        new DailyRotateFile({
            datePattern: 'YYYY-MM-DD',
            filename: `${logPath}/combined-%DATE%.log`,
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            maxFiles: '14d',
            maxSize: '10m',
        }),
        new DailyRotateFile({
            datePattern: 'YYYY-MM-DD',
            filename: `${logPath}/error-%DATE%.log`,
            format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
            level: 'error',
            maxFiles: '14d',
            maxSize: '5m',
        }),
    );
}

const logLevel = process.env.LOG_LEVEL ?? 'info'; // fallback ke info

// Final logger
const logger = winston.createLogger({
    format: winston.format.combine(
        winston.format((info) => {
            const { requestId, payload } = getRequestContext();
            info.requestId = requestId;
            info.payload = sanitizePayload(payload);
            return info;
        })(),
        winston.format.errors({ stack: true }),
        winston.format.splat(),
    ),
    level: logLevel,
    transports,
});

export default logger;
