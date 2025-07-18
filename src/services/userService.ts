// src/services/userService.ts
import { pool } from '../db/pools';
import { ApiError } from '../utils/ApiError';

export async function getUserById(id: string) {
    const { rows } = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [id]);

    const user = rows[0];
    if (!user) throw new ApiError('User not found', 404);

    return user;
}
