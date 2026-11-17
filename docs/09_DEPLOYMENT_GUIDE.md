# SentinelRAG — Production Deployment & Operations Guide

**Document Reference:** `docs/09_DEPLOYMENT_GUIDE.md`  
**Classification:** DevOps & Systems Architecture  
**Project:** SentinelRAG — Secure Retrieval-Augmented Generation Agent  
**Last Updated:** November 14, 2026  
**Status:** **PRODUCTION READY**

---

## 1. System Overview & Deployment Topology

SentinelRAG is a secure, multi-tenant Retrieval-Augmented Generation (RAG) agent designed to safeguard enterprise knowledge retrieval against prompt injection, data exfiltration, and tenant boundary violations.

The system topology consists of three primary tiers:
1. **Frontend Presentation & Reverse Proxy Tier:**
   - Single-Page Application (SPA) built with React 19, TypeScript, and Tailwind CSS v4.
   - Nginx web server handling SPA client-side routing, static asset caching, request body size enforcement, and reverse proxying for backend endpoints.
2. **Application & Security Gateway Tier:**
   - Modular monolith powered by Python 3.12 and FastAPI.
   - PyMuPDF text extraction pipeline and deterministic security scanner.
   - RAG Security Gateway enforcing multi-stage protection (Query Guard, Context Guard, Pre-LLM Gate, Output Guard, and Canary Tracking).
   - Async Google Gemini 1.5 Flash client.
3. **Persistence & Vector Datastore Tier:**
   - **MongoDB 7.0+:** Stores user accounts, hashed refresh sessions, document metadata, audit logs, attack simulation records, and security analytics.
   - **ChromaDB 1.0.9:** Persistent local vector datastore storing sentence embeddings (ONNX all-MiniLM-L6-v2) partitioned by tenant ownership metadata.
   - **Encrypted/Restricted File Storage:** Local filesystem storage holding uploaded PDF binaries outside the web root.

```
                  +----------------------------------------------+
                  |         Client Browser (HTTPS / WSS)         |
                  +----------------------------------------------+
                                         |
                                         v
                         +-------------------------------+
                         |    Nginx Reverse Proxy (80)   |
                         +-------------------------------+
                            /                         \
                           / (SPA Static Assets)       \ (/api/v1/*)
                          v                             v
               +--------------------+        +---------------------+
               | React 19 Client    |        | FastAPI Backend     |
               | (Static Dist)      |        | Port 8000           |
               +--------------------+        +---------------------+
                                                        |
                                +-----------------------+-----------------------+
                                |                       |                       |
                                v                       v                       v
                     +--------------------+   +--------------------+   +------------------+
                     | MongoDB 7.0+       |   | ChromaDB (Local)   |   | PDF Storage      |
                     | Port 27017         |   | /app/chroma_data   |   | /app/uploads     |
                     +--------------------+   +--------------------+   +------------------+
```

---

## 2. Prerequisites & System Requirements

### Hardware Requirements
- **CPU:** Minimum 2 vCPUs (4 vCPUs recommended for concurrent ONNX vector embedding calculations).
- **RAM:** Minimum 4 GB RAM (8 GB recommended for production workloads).
- **Disk Storage:** Minimum 20 GB SSD storage (accommodating MongoDB data, vector collections, and uploaded PDF binaries).

### Software Requirements
- **Operating System:** Ubuntu 22.04 / 24.04 LTS (Production), Windows 10/11 with WSL2, or macOS 13+.
- **Container Engine:** Docker Engine 24.0+ and Docker Compose v2.20+ (for containerized deployments).
- **Bare-Metal Runtimes (if running without Docker):**
  - Python 3.12 (with `pip` and `venv`)
  - Node.js 20 LTS (with `npm`)
  - MongoDB Community Server 7.0+
  - OpenSSL (for generating secure cryptographic keys)

---

## 3. Environment Configuration & Secret Management

SentinelRAG reads all runtime configuration through environment variables via Pydantic Settings (`app/core/config.py`).

### A. Initializing the Configuration File
Copy the provided `.env.example` template:
```bash
# On Linux / macOS:
cp .env.example .env

# On Windows (PowerShell):
Copy-Item .env.example .env
```

### B. Cryptographic Key Generation
Generate a cryptographically secure 32-byte secret key for JWT signing:
```bash
# Using OpenSSL:
openssl rand -hex 32
```
Paste this value into `.env` under `JWT_SECRET`.

### C. Gemini API Key Configuration
1. Navigate to [Google AI Studio](https://aistudio.google.com/).
2. Create a new API Key for your Google Cloud project.
3. Add the key to `.env` under `GEMINI_API_KEY`.

### D. Complete Environment Variable Reference

| Variable Name | Default Value | Required | Description |
|---|---|---|---|
| `APP_ENV` | `development` | Yes | Runtime environment: `development`, `staging`, `production`, or `test`. |
| `APP_HOST` | `0.0.0.0` | Yes | Host address to bind the ASGI server. |
| `APP_PORT` | `8000` | Yes | Port to bind the FastAPI backend. |
| `MONGODB_URI` | `mongodb://localhost:27017` | Yes | MongoDB connection string. Use `mongodb://mongodb:27017` in Docker Compose. |
| `MONGODB_DATABASE` | `sentinelrag` | Yes | Target database name in MongoDB. |
| `CHROMA_PERSIST_DIR` | `./chroma_data` | Yes | Directory for ChromaDB vector SQLite and index persistence. |
| `CHROMA_COLLECTION_NAME` | `sentinelrag_chunks` | Yes | Name of the ChromaDB collection for chunk embeddings. |
| `GEMINI_API_KEY` | *(None)* | Yes | Google Gemini API Key. |
| `GEMINI_MODEL` | `gemini-1.5-flash` | No | Target Gemini model identifier. |
| `JWT_SECRET` | *(None)* | Yes | 32-byte minimum secret key for signing JWT tokens. |
| `JWT_ALGORITHM` | `HS256` | No | Cryptographic algorithm for JWT tokens. |
| `ACCESS_TOKEN_TTL_MINUTES`| `30` | No | Access token expiration duration in minutes. |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | No | Refresh token session expiration duration in days. |
| `REFRESH_COOKIE_NAME` | `sentinel_refresh` | No | Name of the HttpOnly refresh cookie. |
| `REFRESH_COOKIE_SECURE` | `false` | No | Set to `true` in HTTPS production environments. |
| `REFRESH_COOKIE_SAMESITE`| `lax` | No | SameSite policy: `lax` or `strict`. |
| `CORS_ORIGINS` | `["http://localhost:5173"]` | Yes | JSON array of authorized origins for CORS validation. |
| `UPLOAD_DIR` | `./uploads` | Yes | Local disk path for uploaded PDF files. |
| `MAX_UPLOAD_MB` | `20` | No | Maximum allowed file upload size in MB. |
| `LOG_LEVEL` | `INFO` | No | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `VITE_API_BASE_URL` | `""` (empty) | No | Frontend API base URL. Leave empty to use relative `/api` paths with reverse proxy. |

---

## 4. Deployment Option 1: Docker Compose (Recommended)

Docker Compose provides a single-command deployment with isolated networking, persistent volumes, and built-in health monitoring.

### A. Verify Configuration
Ensure `.env` exists in the repository root and has `MONGODB_URI=mongodb://mongodb:27017`.

### B. Build and Launch Containers
```bash
# Build images and start services in detached mode
docker compose up -d --build
```

### C. Verify Service Health
```bash
# Check status of running containers
docker compose ps

# Expected output:
# NAME                   IMAGE                  STATUS                    PORTS
# sentinelrag-mongodb    mongo:7.0              Up (healthy)              27017/tcp
# sentinelrag-backend    sentinelrag-backend    Up (healthy)              0.0.0.0:8000->8000/tcp
# sentinelrag-frontend   sentinelrag-frontend   Up (healthy)              0.0.0.0:80->80/tcp
```

### D. Managing Containers
```bash
# View aggregated real-time logs
docker compose logs -f

# View backend logs only
docker compose logs -f backend

# Stop all services
docker compose down

# Stop all services and purge volumes (WARNING: Deletes persistent data)
docker compose down -v

# Restart a specific service
docker compose restart backend
```

---

## 5. Deployment Option 2: Bare-Metal Setup (Development / Custom Hosting)

### A. Start MongoDB
Ensure MongoDB is running locally on port 27017:
```bash
# Linux (systemd):
sudo systemctl start mongod
sudo systemctl enable mongod

# Windows (Command Prompt or Services):
net start MongoDB
```

### B. Start Backend API
```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# or .venv\Scripts\Activate.ps1 # Windows PowerShell

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Run backend with Uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### C. Start Frontend Client
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run Vite development server
npm run dev
```

---

## 6. Production Hardening & Cloud VPS Setup (Ubuntu 22.04 / 24.04 LTS)

### A. Operating System & Firewall Hardening
Configure Uncomplicated Firewall (UFW) to expose only essential ports:
```bash
# Allow SSH access
sudo ufw allow 22/tcp

# Allow Web traffic
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Deny direct access to MongoDB and Backend ports from public interfaces
sudo ufw deny 27017
sudo ufw deny 8000

# Enable firewall
sudo ufw enable
```

### B. Reverse Proxy & SSL Configuration (Nginx + Let's Encrypt)
On your host VPS, install Nginx and Certbot:
```bash
sudo apt update && sudo apt install -y nginx certbot python3-certbot-nginx
```

Configure `/etc/nginx/sites-available/sentinelrag`:
```nginx
server {
    server_name yourdomain.com;

    client_max_body_size 25M;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable the configuration and obtain an SSL certificate:
```bash
sudo ln -s /etc/nginx/sites-available/sentinelrag /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Obtain free TLS certificate via Let's Encrypt
sudo certbot --nginx -d yourdomain.com
```

### C. Production Cookie Security
In `.env`, set:
```bash
REFRESH_COOKIE_SECURE=true
CORS_ORIGINS=["https://yourdomain.com"]
```

---

## 7. Persistent Storage, Backup & Disaster Recovery

SentinelRAG stores state across three distinct persistent targets:
1. **MongoDB Database:** User credentials, sessions, documents, conversations, events.
2. **ChromaDB Vector Store:** ONNX embeddings and HNSW indexes.
3. **PDF Storage Directory:** Raw PDF documents uploaded by users.

### A. MongoDB Backup & Restoration

**Creating a Backup:**
```bash
# Backup containerized MongoDB:
docker exec -t sentinelrag-mongodb mongodump --db sentinelrag --out /data/db/backup_$(date +%Y%m%d)

# Copy backup archive to host:
docker cp sentinelrag-mongodb:/data/db/backup_$(date +%Y%m%d) ./backups/mongo/
```

**Restoring from Backup:**
```bash
# Copy backup into container:
docker cp ./backups/mongo/backup_20261114 sentinelrag-mongodb:/data/db/restore_data

# Restore database:
docker exec -t sentinelrag-mongodb mongorestore --db sentinelrag /data/db/restore_data/sentinelrag --drop
```

### B. ChromaDB Vector Store Backup
ChromaDB uses SQLite and local file segments for index storage:
```bash
# Archiving persistent vector directory:
tar -czvf ./backups/chroma/chroma_backup_$(date +%Y%m%d).tar.gz ./chroma_data/

# Restoring vector directory:
tar -xzvf ./backups/chroma/chroma_backup_20261114.tar.gz -C ./
```

### C. Uploaded Documents Backup
```bash
# Archiving uploaded PDFs:
tar -czvf ./backups/uploads/uploads_backup_$(date +%Y%m%d).tar.gz ./uploads/

# Restoring uploaded PDFs:
tar -xzvf ./backups/uploads/uploads_backup_20261114.tar.gz -C ./
```

---

## 8. Health Checks, Monitoring & Operational Diagnostics

### A. Health Check Endpoints

| Endpoint | Method | Purpose | Healthy Status |
|---|---|---|---|
| `/api/v1/ping` | `GET` | Instant liveness check (no DB dependency). | `200 OK` (`pong: true`) |
| `/api/v1/health` | `GET` | Overall application health & composite status. | `200 OK` (`status: healthy`) |
| `/api/v1/health/database` | `GET` | MongoDB connection status and latency. | `200 OK` (`connected: true`) |
| `/api/v1/health/vector-store` | `GET` | ChromaDB collection availability. | `200 OK` (`status: ready`) |

### B. Troubleshooting Matrix

| Problem | Root Cause | Remediation |
|---|---|---|
| **MongoDB Connection Failure** (`ServerSelectionTimeoutError`) | MongoDB service is not started, or incorrect URI specified in `.env`. | Verify MongoDB is running (`systemctl status mongod` or `docker compose ps`). Check that `MONGODB_URI` points to `mongodb://mongodb:27017` in Docker or `localhost:27017` on bare-metal. |
| **ChromaDB Initialization Error** (`PostHog / SQLite locked`) | Multiple concurrent processes accessing `./chroma_data` or permission issue. | Ensure only one backend worker process holds the persistent ChromaDB directory. Verify write permissions for the directory. |
| **Gemini API 403 / 429 Errors** | Invalid `GEMINI_API_KEY` or quota limit reached on Google AI Studio. | Verify key at [Google AI Studio](https://aistudio.google.com/). Ensure rate limits are not exceeded. |
| **CORS Rejected on Frontend** | Request origin not listed in backend `CORS_ORIGINS`. | Update `CORS_ORIGINS` in `.env` to include your exact frontend host (e.g. `["http://localhost:5173", "https://yourdomain.com"]`). |
| **Refresh Cookie Not Sent** | `REFRESH_COOKIE_SECURE=true` on HTTP connection. | On non-HTTPS (localhost) environments, set `REFRESH_COOKIE_SECURE=false`. Set to `true` only when TLS/HTTPS is active. |
| **File Upload 413 Entity Too Large** | Upload exceeds `MAX_UPLOAD_MB` or Nginx `client_max_body_size`. | Increase `MAX_UPLOAD_MB` in `.env` and `client_max_body_size 25M;` in `nginx.conf`. |

