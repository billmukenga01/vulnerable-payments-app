# Project Setup & Run Instructions

## Prerequisites
- Node.js (v20+ recommended, as Vite 7 requires it)
- npm

## Server
The server is an Express app using Prisma with SQLite.

1. **Navigate to the server directory:**
   ```bash
   cd server
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Database Setup:**
   Ensure your `.env` file is configured (default `DATABASE_URL="file:./dev.db"` is set).
   Run migrations to set up the SQLite database:
   ```bash
   npx prisma migrate dev --name init
   ```

4. **Start the Development Server:**
   ```bash
   npm run dev
   ```
   This runs the server using `nodemon`.

## Client
The client is a React application built with Vite.

1. **Navigate to the client directory:**
   ```bash
   cd client
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Start the Development Server:**
   ```bash
   npm run dev
   ```
   
   > **Note:** The project uses Vite 7, which requires Node.js version 20 or higher. If you are on Node 18, you might encounter warnings or errors.

4. **Build for Production:**
   ```bash
   npm run build
   ```
