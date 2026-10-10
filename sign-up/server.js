require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// In-memory stores — swap for a real DB in production
const users = [];   // { name, email, password, verified }
const otps = new Map(); // email -> { code, expiresAt, attempts }

const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_ATTEMPTS = 5;

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function generateOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

/* ---------- STEP 1: Request signup → send OTP ---------- */
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  if (users.find((u) => u.email === email)) {
    return res.status(409).json({ error: 'Email already registered.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const code = generateOtp();

  // Store pending user + OTP (overwrites any previous OTP for this email)
  users.push({ name, email, password: hashedPassword, verified: false });
  otps.set(email, {
    code,
    expiresAt: Date.now() + OTP_TTL_MS,
    attempts: 0,
  });

  try {
    await transporter.sendMail({
      from: `"My App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your verification code',
      text: `Your code is ${code}. It expires in 10 minutes.`,
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;padding:24px">
          <h2>Verify your email</h2>
          <p>Enter this code to finish signing up:</p>
          <div style="font-size:32px;font-weight:700;letter-spacing:8px;
                      background:#f4f4f8;padding:16px;text-align:center;
                      border-radius:8px;margin:20px 0">${code}</div>
          <p style="color:#666;font-size:13px">Expires in 10 minutes. If you didn't sign up, ignore this email.</p>
        </div>
      `,
    });
    console.log(`OTP for ${email}: ${code}`);
  } catch (err) {
    console.error('Email failed:', err.message);
    return res.status(500).json({ error: 'Could not send verification email.' });
  }

  res.json({ ok: true, message: 'Verification code sent. Check your inbox.' });
});

/* ---------- STEP 2: Verify OTP ---------- */
app.post('/api/verify-otp', (req, res) => {
  const { email, code } = req.body;

  const record = otps.get(email);
  if (!record) {
    return res.status(400).json({ error: 'No code requested for this email.' });
  }
  if (Date.now() > record.expiresAt) {
    otps.delete(email);
    return res.status(400).json({ error: 'Code expired. Request a new one.' });
  }
  if (record.attempts >= MAX_ATTEMPTS) {
    otps.delete(email);
    return res.status(429).json({ error: 'Too many attempts. Request a new code.' });
  }
  if (record.code !== code) {
    record.attempts++;
    return res.status(400).json({ error: 'Incorrect code.' });
  }

  const user = users.find((u) => u.email === email);
  if (!user) {
    return res.status(400).json({ error: 'User not found.' });
  }

  user.verified = true;
  otps.delete(email);

  res.json({ ok: true, message: 'Email verified! You can now log in.' });
});

/* ---------- Resend OTP ---------- */
app.post('/api/resend-otp', async (req, res) => {
  const { email } = req.body;
  const user = users.find((u) => u.email === email);
  if (!user || user.verified) {
    return res.status(400).json({ error: 'Cannot resend for this email.' });
  }

  const code = generateOtp();
  otps.set(email, { code, expiresAt: Date.now() + OTP_TTL_MS, attempts: 0 });

  try {
    await transporter.sendMail({
      from: `"My App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Your new verification code',
      text: `Your new code is ${code}. It expires in 10 minutes.`,
    });
    console.log(`Resent OTP for ${email}: ${code}`);
  } catch (err) {
    return res.status(500).json({ error: 'Could not resend email.' });
  }

  res.json({ ok: true, message: 'New code sent.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));