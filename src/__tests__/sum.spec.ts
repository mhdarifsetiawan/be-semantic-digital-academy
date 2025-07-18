import request from 'supertest';
import { describe, it, expect } from 'vitest';
import express from 'express';
// import healthRoute from '../src/routes/health';
import healthRoutes from '../../src/routes/v1/health';

const app = express();
app.use(healthRoutes);

describe('GET /healthz', () => {
    it('should return 200 and status ok', async () => {
        const res = await request(app).get('/healthz');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ status: 'ok' });
    });
});
