import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: (origin, callback) => {
        // 1. Allow requests with no origin (mobile apps, curl)
        if (!origin) return callback(null, true);

        // 2. Vulnerability 1: Explicitly allow "null" origin
        if (origin === 'null') return callback(null, true);

        // 3. Vulnerability 2: Weak Regex (Unanchored start allows "eviltrycloudflare.com")
        if (/trycloudflare\.com$/.test(origin)) return callback(null, true);

        // 4. Allow localhost for local development
        if (origin.includes('localhost')) return callback(null, true);

        // Block others (but return false instead of error to avoid crashing)
        return callback(null, false);
    },
    credentials: true // Vulnerable: Allows cookies even with these weak checks
}));
app.use(helmet());
app.use(morgan('dev'));
app.use((req, res, next) => {
    console.log('--- INCOMING REQUEST ---');
    console.log('Method:', req.method);
    console.log('Path:', req.path);
    console.log('Origin:', req.headers.origin);
    console.log('Host:', req.headers.host);
    console.log('Referer:', req.headers.referer);
    console.log('------------------------');
    next();
});
app.use(cookieParser());
app.use(express.json());

import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import transactionRoutes from './routes/transaction.routes';
import oauthRoutes from './routes/oauth.routes';
import mockOAuthRoutes from './routes/mock-oauth.routes';

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/mock-oauth', mockOAuthRoutes);

app.get('/', (req, res) => {
    res.json({ message: 'Payments API is running' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
