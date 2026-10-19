# ==========================================
# Stage 1: Build the React 19 Frontend
# ==========================================
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Production Python Backend Runtime
# ==========================================
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ./backend/requirements.txt && \
    python -m spacy download en_core_web_sm

# Copy datasets, docs, and application code
COPY datasets/ ./datasets/
COPY backend/ ./backend/

# Copy compiled frontend from Stage 1 into the location expected by FastAPI
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Initialize SQLite database and train baseline models
RUN python -m app.database.init_db && \
    python -m app.ml.train_classifier

EXPOSE 8000

# Start Uvicorn on dynamic port (Render/Railway injects $PORT)
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
