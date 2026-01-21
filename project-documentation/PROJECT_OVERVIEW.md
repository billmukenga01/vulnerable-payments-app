# 🛡️ Vulnerable Payments Application - Project Overview

This document provides a complete breakdown of the "Vulnerable Payments Application," a purposefully insecure web app designed for educational penetration testing, specifically focusing on **CORS (Cross-Origin Resource Sharing)** vulnerabilities.

---

## 🏗️ Architecture & Components

The application follows a modern microservices-style architecture, containerized with Docker.

### 1. 🎨 Frontend (Client)
- **Tech Stack:** React, TypeScript, Vite.
- **Location:** `/client`
- **Role:** Provides the user interface for logging in and viewing dashboard data.
- **Key Configuration:**
    - uses `VITE_API_BASE_URL` to know where the backend lives (this points to our Cloudflare Tunnel).
    - `vite.config.ts` is configured to allow external hosts (Cloudflare).

### 2. ⚙️ Backend (Server)
- **Tech Stack:** Node.js, Express, TypeScript, Prisma ORM.
- **Location:** `/server`
- **Role:** Handles API requests, processes logic, and connects to the database.
- **Vulnerability:**
    - **CORS Misconfiguration:** In `src/index.ts`, the CORS policy is set to `origin: true` and `credentials: true`. This allows *any* website to make authenticated requests to this API, simulating a critical security flaw.

### 3. 🗄️ Database
- **Tech Stack:** SQLite (via Prisma).
- **Location:** `/server/dev.db` (inside the container).
- **Role:** Stores user credentials and payment data.
- **Note:** In this specific Docker setup, the database is ephemeral. If you destroy the server container, the data resets (unless you mount a volume, but for this lab, we keep it simple).

---

## 📦 Containerization & Hosting

We avoid "works on my machine" issues by using Docker.

### 🐳 Docker Containers
We run two distinct containers connected by a private network (`vulnerable-net`):
1.  **`vulnerable-server`**: Runs the backend APIs on port 3000.
2.  **`vulnerable-client`**: Runs the frontend UI on port 5173.

### 🌐 Public Access (Cloudflare Tunnels)

We have automated the tunnel setup script as well.

**1. Run the Tunnel Script:**
```bash
./start_tunnels.sh
```
This will:
-   Download `cloudflared` if you don't have it.
-   Start tunnels for both Backend (3000) and Frontend (5173).
-   **Output your PUBLIC URLs.**

**2. Important Step:**
Copy the **Backend URL** from the script output and paste it into `deploy.sh`. Then run `./deploy.sh client`.

---

## 🔄 Development Workflow: How to Apply Changes

We have automated the deployment process. You do not need to run complex Docker commands manually.

### The Automation Script: `deploy.sh`

Located in the root directory, this script handles stopping old containers, rebuilding images with your latest code changes, and starting them up again.

**Usage:**

1.  **Make your code changes** (e.g., modify `client/src/App.tsx` or `server/src/index.ts`).
2.  **Run the script:**

| Command | Action |
| :--- | :--- |
| `./deploy.sh all` | **Recommended.** Rebuilds and restarts **BOTH** Client and Server. |
| `./deploy.sh server` | Faster. Rebuilds only the Backend (use if you only changed server code). |
| `./deploy.sh client` | Faster. Rebuilds only the Frontend (use if you only changed UI code). |

### ⚠️ Important Note on URLs
If you restart your Cloudflare Tunnel, you will get a **NEW** public URL for the backend. You must:
1.  Copy the new Backend URL.
2.  Update the `BACKEND_TUNNEL_URL` variable inside `deploy.sh`.
3.  Run `./deploy.sh client` so the Frontend knows the new API address.
