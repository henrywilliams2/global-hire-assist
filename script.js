import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import authRouter from './routes/auth.js';
import paymentsRouter from './routes/payments.js';
import formRouter from './routes/form.js';
import webhookRouter from './routes/webhook.js';
import dashboardRouter from './routes/dashboard.js';

dotenv.config();
const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use('/auth', authRouter);
app.use('/payments', paymentsRouter);
app.use('/form', formRouter);
app.use('/webhook', webhookRouter);
app.use('/dashboard', dashboardRouter);

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log(`Global Hire Assist API listening on port ${PORT}`);
});
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';

const router = express.Router();
const users = new Map();
const JWT_EXPIRES_IN = '24h';
const COOKIE_NAME = 'gh_jwt';

function generateToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET || 'secret', { expiresIn: JWT_EXPIRES_IN });
}

router.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (users.has(email)) return res.status(400).json({ error: 'User exists' });

  const hash = await bcrypt.hash(password, 10);
  const user = { id: uuidv4(), email, passwordHash: hash, createdAt: Date.now() };
  users.set(email, user);

  const token = generateToken({ userId: user.id, email: user.email });
  res.cookie(COOKIE_NAME, token, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.json({ ok: true, user: { id: user.id, email: user.email } });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, user.passwordHash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = generateToken({ userId: user.id, email: user.email });
  res.cookie(COOKIE_NAME, token, { httpOnly: true, secure: true, sameSite: 'lax' });
  res.json({ ok: true, user: { id: user.id, email: user.email } });
});

router.post('/forgot-password', (req, res) => {
  res.json({ ok: true, message: 'Password reset link would be sent if SMTP configured.' });
});

export default router;
import express from 'express';
import Stripe from 'stripe';
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

router.post('/create-checkout-session', async (req, res) => {
  try {
    const { applicantId, item = 'Visa Service Fee', amount } = req.body;
    if (!applicantId || !amount) return res.status(400).json({ error: 'Invalid payload' });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: item },
          unit_amount: Math.round(Number(amount)),
        },
        quantity: 1,
      }],
      mode: 'payment',
      success_url: `${process.env.APP_BASE_URL}/payments-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.APP_BASE_URL}/payments?cancel=true`,
      metadata: { applicantId, item, amount },
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error('Checkout session error:', err);
    res.status(500).json({ error: 'Unable to create checkout session' });
  }
});

// Webhook
import bodyParser from 'body-parser';
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

router.post('/webhook', bodyParser.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = Stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const { applicantId, item, amount } = session.metadata;
    // Persist payment status to DB in production
    console.log(`Payment completed for ${applicantId} - ${item} - ${amount} (${session.id})`);
  }

  res.status(200).json({ received: true });
});

export default router;
import express from 'express';
const router = express.Router();

router.get('/redirect', (req, res) => {
  res.redirect('https://formspree.io/f/manllvow');
});

router.post('/fallback', (req, res) => {
  res.json({ ok: true, message: 'Form fallback received' });
});

export default router;
import express from 'express';
import jwt from 'jsonwebtoken';
const router = express.Router();

const SECRET = process.env.JWT_SECRET || 'secret';
function authGuard(req, res, next) {
  const token = req.cookies?.gh_jwt;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

router.get('/data', authGuard, (req, res) => {
  res.json({
    profile: { email: 'user@example.com', name: 'Applicant' },
    applications: [
      { id: 'APP-001', status: 'Draft' },
      { id: 'APP-002', status: 'Under Review' },
    ],
    payments: [
      { id: 'PAY-001', status: 'Pending', amount: 5000 },
    ],
  });
});

export default router;
PORT=5050
APP_BASE_URL=https://www.globalhireassist.com
JWT_SECRET=your_jwt_secret
STRIPE_PUBLISHABLE_KEY=pk_test_51SP8qw...
STRIPE_SECRET_KEY=sk_test_51SP8qw...
STRIPE_WEBHOOK_SECRET=whsec_...
FORMSPREE_ENDPOINT=https://formspree.io/f/manllvow
DATABASE_URL=sqlite:///db.sqlite
{
  "name": "globalhireassist-server",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "cookie-parser": "^1.4.6",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "stripe": "^8.406.0",
    "sqlite3": "^5.1.4"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}
