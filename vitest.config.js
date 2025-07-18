// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        coverage: {
            provider: 'v8',
            include: ['src/routes/v1/**/*.{ts,tsx}'], // ✅ hanya folder ini yang di-cover
            reporter: ['text', 'html'],
        },
    },
});
