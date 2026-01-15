import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
    origin: true, // Vulnerable: Reflects the request origin
    credentials: true // Vulnerable: Allows cookies/auth headers with the reflected origin
}));
app.use(helmet());
app.use(morgan('dev'));
app.use(express.json());

import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import transactionRoutes from './routes/transaction.routes';

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/transactions', transactionRoutes);

app.get('/', (req, res) => {
    res.json({ message: 'Payments API is running' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
