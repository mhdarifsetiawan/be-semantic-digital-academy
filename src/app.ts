import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';

import { errorHandler } from './middleware/errorHandler';
import { requestLogger } from './middleware/loggerMiddleware';
import { requestIdMiddleware } from './middleware/requestMiddleware';
import v1Routes from './routes/v1';

dotenv.config();

if (!process.env.JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET is not defined.');
    process.exit(1);
}

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.text());
app.use(express.raw({ type: 'application/octet-stream' }));

app.use(cookieParser());
app.use(
    cors({
        credentials: true,
        origin: 'http://localhost:3000',
    }),
);

app.use(requestIdMiddleware);
app.use(requestLogger);

app.use('/api/v1', v1Routes);

app.use(errorHandler);

export default app;
