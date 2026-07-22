# AI Code Review & Security Analysis Agent

A production-ready full-stack platform for static application security testing (SAST), code quality auditing, and interactive code review remediation.

---

## 🚀 Recent Updates & Fixes (Applied)

We have updated the codebase to resolve critical environment setup bugs:
1. **SQLite Database Fallback Configured**: The database configuration is now pointing to a local SQLite database file (`ai_code_review_db.db`) inside the `.env` file. This lets you run the application locally on your laptop **without needing a running Docker or PostgreSQL instance**!
2. **Modern ChromaDB Client Setup**: Fixed legacy config settings in `rag_service.py` to use `chromadb.PersistentClient(path=".chromadb_data")`. This prevents backend crashes and connects to a persistent local vector collection correctly.
3. **Conversational Agent Routing Fixed**: Corrected rule ID checks in the Q&A node logic in `conversation_agent.py` to map specific questions (like SQL Injection or Command execution) to their actual scanner findings.

---

## 💻 Setup and Running Locally (Without Docker)

Since dependencies are already configured, follow these simple steps to start the application:

### Step 1: Start the Backend server
1. Open a terminal and navigate to the project directory.
2. Activate the python virtual environment:
   ```bash
   source .venv/bin/activate
   ```
3. Start the FastAPI backend server:
   ```bash
   uvicorn backend.app.main:app --reload --port 8000
   ```
   *The Swagger API documentation will be available at: http://localhost:8000/docs*

### Step 2: Start the Frontend React Client
1. Open a **second terminal window** and navigate to the project directory.
2. Run the Vite development server:
   ```bash
   npm run frontend:dev
   ```
3. Open your browser and navigate to: **`http://localhost:3000`**

---

## 🐳 Running with Docker Compose (If Docker is installed & running)

If you prefer to run the entire PostgreSQL, FastAPI, Nginx, and React client stack inside containers:

1. Launch **Docker Desktop** on your computer.
2. Copy configuration file:
   ```bash
   cp .env.example .env
   ```
3. Run container orchestrations:
   ```bash
   npm run docker:up
   ```
4. Access the portal at: **`http://localhost:3000`**

---

## 🧪 Executing Verification Tests

Run the backend pytest suite:
```bash
./.venv/bin/python -m pytest tests/
```

Run the frontend test suite:
```bash
npm run test --workspace=frontend
```
