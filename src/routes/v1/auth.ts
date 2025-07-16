// src/routes/auth.ts
import { Router } from 'express';
import { pool } from '../../db';
import bcrypt from 'bcrypt';
import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import { authenticateToken, AuthRequest } from '../../middleware/auth';
import { authRateLimiter } from '../../middleware/rateLimiter';
import crypto from 'crypto';
import dayjs from 'dayjs';
// import nodemailer from 'nodemailer'; // kalau kamu pakai email service

const router = Router();

// const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
// const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

const ACCESS_TOKEN_DURATION_MS = 1 * 60 * 1000;
const REFRESH_TOKEN_DURATION_MS = 3 * 60 * 1000;
const ACCESS_TOKEN_EXPIRES_IN = '1m';
const REFRESH_TOKEN_EXPIRES_IN = '2m';

const RESET_TOKEN_EXPIRATION_MINUTES = 15;


if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not defined in .env');
}
const JWT_SECRET: Secret = process.env.JWT_SECRET;

// Utility: generate JWT
const generateAccessToken = (userId: string) => {
    const payload = { userId };
    //   const options = { expiresIn: ACCESS_TOKEN_EXPIRES_IN as any };
    return jwt.sign(payload, JWT_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    } as SignOptions)
};

const generateRefreshToken = (userId: string) => {
    const payload = { userId, type: 'refresh' };
    //   const options = { expiresIn: REFRESH_TOKEN_EXPIRES_IN as any };
    return jwt.sign(payload, JWT_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRES_IN,
    } as SignOptions);
};

// 🟢 POST /register
router.post('/register', authRateLimiter, async (req, res) => {
  const { email, password, name } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, name) VALUES ($1, $2, $3) RETURNING id, email, name',
      [email, hashedPassword, name]
    );

    const user = result.rows[0];
    res.status(201).json({ user });
  } catch (error: any) {
    if (error.code === '23505') {
      return res.status(400).json({ message: 'Email already exists' });
    }
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 🟢 POST /login
router.post('/login', authRateLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ message: 'Invalid credentials' });

    // ✅ Generate tokens
    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id);

    // Simpan refreshToken ke DB
    const expiresAt = new Date(Date.now() + REFRESH_TOKEN_DURATION_MS);
    await pool.query(
      'INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES ($1, $2, $3)',
      [refreshToken, user.id, expiresAt]
    );

    // Kirim token via cookie
    res
    .cookie('accessToken', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: ACCESS_TOKEN_DURATION_MS,
      sameSite: 'lax', // ✅ penting untuk browser support
      path: '/',       // ✅ agar tersedia di semua route
    })
    .cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: REFRESH_TOKEN_DURATION_MS,
      sameSite: 'lax',
      path: '/',
    })
    .json({ rc: '00', message: 'Login successful' });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 🟠 POST /logout
router.post('/logout', async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  // 1. Hapus refresh token dari database jika ada
  if (refreshToken) {
    try {
      await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    } catch (err) {
      console.error('Failed to delete refresh token from DB:', err);
      // Lanjut hapus cookie meskipun query gagal
    }
  }

  // 2. Hapus cookie dari browser
  res
    .clearCookie('accessToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    })
    .clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
    })
    .status(200)
    .json({ rc: '00', message: 'Logged out successfully' });
});

router.post('/refresh-token', async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ message: 'No refresh token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string, type: string };

    if (decoded.type !== 'refresh') {
      return res.status(400).json({ message: 'Invalid token type' });
    }

    // Cek apakah token ada di DB
    const result = await pool.query(
      'SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > NOW()',
      [token]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Refresh token not found or expired' });
    }

    const userId = decoded.userId;
    const newAccessToken = generateAccessToken(userId);

    res.cookie('accessToken', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: ACCESS_TOKEN_DURATION_MS
    });

    res.json({ message: 'Access token refreshed' });
  } catch (err) {
    console.error(err);
    res.status(403).json({ message: 'Invalid or expired refresh token' });
  }
});

router.get('/me', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const userId = req.userId;
    const result = await pool.query(
      'SELECT id, email, name, created_at FROM users WHERE id = $1',
      [userId]
    );

    const user = result.rows[0];
    if (!user) return res.status(404).json({ rc: '01', message: 'User not found' });

    res.json({ user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// 🟡 POST /forgot-password
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email wajib diisi' });
  }

  try {
    const userResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    const user = userResult.rows[0];

    if (!user) {
      // Jangan bocorkan bahwa email tidak ditemukan
      return res.status(200).json({ message: 'Jika email terdaftar, kami akan mengirim link reset password.' });
    }

    // Buat token random
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = dayjs().add(RESET_TOKEN_EXPIRATION_MINUTES, 'minute').toDate();

    // Simpan token ke tabel
    await pool.query(
      `INSERT INTO password_reset_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)`,
      [user.id, token, expiresAt]
    );

    // Buat URL reset
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${token}`;

    // Kirim email atau tampilkan URL (saat dev)
    console.log(`🔗 Reset password link: ${resetUrl}`);

    // Kalau pakai nodemailer, kirim email di sini

    return res.status(200).json({
      message: 'Jika email terdaftar, kami akan mengirim link reset password.',
      resetUrl: process.env.NODE_ENV === 'development' ? resetUrl : undefined
    });

  } catch (err) {
    console.error('❌ Error di /forgot-password:', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
});


// 🔄 Reset password
router.post('/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;

  if (!password || password.length < 6) {
    return res.status(400).json({ message: 'Password minimal 6 karakter' });
  }

  try {
    // 1. Cek apakah token valid dan belum kedaluwarsa
    const result = await pool.query(
      `SELECT user_id FROM password_reset_tokens WHERE token = $1 AND expires_at > NOW()`,
      [token]
    );

    const data = result.rows[0];
    if (!data) {
      return res.status(400).json({ message: 'Token tidak valid atau sudah kedaluwarsa' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    // 2. Update password user
    await pool.query(
      `UPDATE users SET password = $1 WHERE id = $2`,
      [hashedPassword, data.user_id]
    );

    // 3. Hapus token agar tidak bisa dipakai ulang
    await pool.query(`DELETE FROM password_reset_tokens WHERE token = $1`, [token]);

    res.json({ message: 'Password berhasil direset' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Terjadi kesalahan pada server' });
  }
});






export default router;