/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unnecessary-condition */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { NextFunction, Request, Response } from 'express';

import { ApiError } from '../../utils/ApiError';
import logger from '../../utils/logger';
import asyncLocalStorage from '../../utils/requestContext';

// Cek jika body JSON tidak kosong
export const validateJsonPayload = (req: Request, res: Response, next: NextFunction) => {
    if (!req.body || Object.keys(req.body).length === 0) {
        logger.info('Validator: JSON body is empty');
        next(new ApiError('JSON body cannot be empty', 400));
        return;
    }

    logger.info('Validator: JSON payload validated');
    res.locals.payload = req.body;
    next();
};

// Cek jika plaintext payload (encrypted) tidak kosong
export const validateEncryptedPayload = (req: Request, res: Response, next: NextFunction) => {
    if (!req.body || typeof req.body !== 'string' || req.body.trim() === '') {
        logger.info('Validator: Encrypted body is empty or invalid');
        next(new ApiError('Encrypted payload is required', 400));
        return;
    }

    logger.info('Validator: Encrypted payload validated');
    res.locals.payload = req.body;
    next();
};

// Cek jika form-urlencoded payload tidak kosong
export const validateFormPayload = (req: Request, res: Response, next: NextFunction) => {
    if (!req.body || Object.keys(req.body).length === 0) {
        logger.info('Validator: Form payload is empty');
        next(new ApiError('Form payload cannot be empty', 400));
        return;
    }

    logger.info('Validator: Form payload validated');
    res.locals.payload = req.body;
    next();
};

// Cek jika query string (ex: GET /search?page=1&keyword=abc)
function validateQueryPayload(req: Request, res: Response, next: NextFunction) {
    if (!req.query || Object.keys(req.query).length === 0) {
        next(new ApiError('Empty query parameters', 400));
        return;
    }

    logger.info('Validator: Query string validated');
    res.locals.payload = req.query;
    next();
}

// Middleware utama yang mendeteksi format payload
export const flexiblePayloadValidator = (req: Request, res: Response, next: NextFunction) => {
    const method = req.method.toUpperCase();
    const contentType = req.headers['content-type'];

    // Simpan payload ke res.locals dan ke context
    let payload: unknown;

    if (req.body && Object.keys(req.body).length > 0) {
        payload = req.body;
    } else if (req.query && Object.keys(req.query).length > 0) {
        payload = req.query;
    } else if (req.params && Object.keys(req.params).length > 0) {
        payload = req.params;
    }

    if (payload) {
        res.locals.payload = payload;

        // ✅ Simpan ke asyncLocalStorage
        const store = asyncLocalStorage.getStore();
        if (store) {
            store.payload = JSON.stringify(payload);
        }
    }

    if (method === 'GET') {
        validateQueryPayload(req, res, next);
        return;
    }

    if (contentType?.includes('application/json')) {
        logger.info('Payload Validator: JSON Content-Type detected');
        validateJsonPayload(req, res, next);
        return;
    }

    if (contentType?.includes('text/plain')) {
        logger.info('Payload Validator: Encrypted Content-Type detected');
        validateEncryptedPayload(req, res, next);
        return;
    }

    if (contentType?.includes('application/x-www-form-urlencoded')) {
        logger.info('Payload Validator: Form-urlencoded Content-Type detected');
        validateFormPayload(req, res, next);
        return;
    }

    logger.error('Payload Validator: Unsupported Content-Type');

    next(new ApiError('Unsupported Content-Type', 415));
};
