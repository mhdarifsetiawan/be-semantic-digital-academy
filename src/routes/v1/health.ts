// src/routes/health.ts
import { Router } from 'express';

const router = Router();

router.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

export default router;
