import { NextFunction, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

import asyncLocalStorage from '../utils/requestContext';

export const requestIdMiddleware = (req: Request, res: Response, next: NextFunction) => {
    const requestId = uuidv4();

    asyncLocalStorage.run({ requestId }, () => {
        next();
    });
};
