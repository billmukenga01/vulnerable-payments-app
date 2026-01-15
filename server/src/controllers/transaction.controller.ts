import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z, ZodError } from 'zod';

const prisma = new PrismaClient();

const sendMoneySchema = z.object({
    receiverEmail: z.string().email(),
    amount: z.number().positive(),
});

export const sendMoney = async (req: Request, res: Response) => {
    // @ts-ignore
    const senderId = req.userId;

    try {
        const { receiverEmail, amount } = sendMoneySchema.parse(req.body);

        const sender = await prisma.user.findUnique({ where: { id: senderId } });
        const receiver = await prisma.user.findUnique({ where: { email: receiverEmail } });

        if (!sender) return res.status(404).json({ message: 'Sender not found' });
        if (!receiver) return res.status(404).json({ message: 'Receiver not found' });
        if (sender.id === receiver.id) return res.status(400).json({ message: 'Cannot send money to yourself' });
        if (sender.balance < amount) return res.status(400).json({ message: 'Insufficient funds' });

        // Transaction
        const transaction = await prisma.$transaction(async (tx) => {
            // Deduct from sender
            await tx.user.update({
                where: { id: senderId },
                data: { balance: { decrement: amount } },
            });

            // Add to receiver
            await tx.user.update({
                where: { id: receiver.id },
                data: { balance: { increment: amount } },
            });

            // Create transaction record
            return await tx.transaction.create({
                data: {
                    amount,
                    senderId,
                    receiverId: receiver.id,
                    status: 'COMPLETED',
                },
                include: {
                    sender: { select: { name: true, email: true } },
                    receiver: { select: { name: true, email: true } },
                },
            });
        });

        res.status(201).json(transaction);
    } catch (error) {
        if (error instanceof ZodError) {
            return res.status(400).json({ errors: (error as ZodError).errors });
        }
        console.error(error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const getHistory = async (req: Request, res: Response) => {
    // @ts-ignore
    const userId = req.userId;

    try {
        const transactions = await prisma.transaction.findMany({
            where: {
                OR: [
                    { senderId: userId },
                    { receiverId: userId },
                ],
            },
            orderBy: { createdAt: 'desc' },
            include: {
                sender: { select: { name: true, email: true } },
                receiver: { select: { name: true, email: true } },
            },
        });

        res.json(transactions);
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
};
