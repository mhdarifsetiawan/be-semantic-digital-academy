import { Router } from 'express';

import authRoutes from './auth';
import healthRoutes from './health';
import userRoutes from './user';

const router = Router();

router.use('/', authRoutes); // /login, /register
router.use('/', healthRoutes); // /healthz
router.use('/', userRoutes); // /user

export default router;
