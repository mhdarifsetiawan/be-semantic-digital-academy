import { Router } from 'express';
import authRoutes from './auth';
import healthRoutes from './health';

const router = Router();

router.use(authRoutes);     // /api/v1/register, /login, etc
router.use(healthRoutes);   // /api/v1/healthz

export default router;
