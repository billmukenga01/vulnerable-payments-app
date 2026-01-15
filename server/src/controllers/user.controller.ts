import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export const getUser = async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
        const user = await prisma.user.findUnique({
            where: { id },
            select: { id: true, name: true, email: true, createdAt: true },
        });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getBalance = async (req: Request, res: Response) => {
    const { id } = req.params;
    // @ts-ignore
    const currentUserId = req.userId;

    if (id !== currentUserId) {
        return res.status(403).json({ message: 'Forbidden' });
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id },
            select: { balance: true },
        });
        if (!user) return res.status(404).json({ message: 'User not found' });
        res.json({ balance: user.balance });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};
