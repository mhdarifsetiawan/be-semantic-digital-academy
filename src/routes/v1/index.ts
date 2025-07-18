import { Router } from 'express';
import healthRoutes from './health';
import authRoutes from './auth';
import userRoutes from './user';

const router = Router();

router.use('/', authRoutes); // /login, /register
router.use('/', healthRoutes); // /healthz
router.use('/', userRoutes); // /user

export default router;
