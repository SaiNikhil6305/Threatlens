# ThreatLens Cloud Deployment Guide (Render & Railway)

This guide walks you through deploying **ThreatLens** to the cloud for free using either **Render** or **Railway** directly from your GitHub repository:
`https://github.com/SaiNikhil6305/Threatlens`

---

## Option 1: 1-Click Deployment on Render (Recommended & Free)

Render provides a generous free tier for web services and natively supports the `Dockerfile` and `render.yaml` included in this repository.

### Step 1: Sign Up / Log In
1. Go to [https://render.com](https://render.com) and log in with your GitHub account.

### Step 2: Create a New Web Service
1. In the Render Dashboard, click **New +** and select **Web Service** (or **Blueprint**).
2. Under *Connect a repository*, choose `SaiNikhil6305/Threatlens`.
3. Configure the service settings:
   - **Name:** `threatlens` (or your preferred name)
   - **Region:** Any (e.g., *Oregon, USA* or *Frankfurt, EU*)
   - **Branch:** `main`
   - **Runtime:** **Docker** *(Render will auto-detect the root `Dockerfile`)*
   - **Instance Type:** **Free**

### Step 3: Deploy
1. Click **Deploy Web Service**.
2. Render will automatically:
   - Build the React 19 frontend assets.
   - Install Python dependencies and the spaCy NLP model.
   - Initialize the database and train the machine learning models.
   - Launch the production server on port `$PORT`.
3. Once the build completes (usually 2–3 minutes), your app will be live at:
   `https://threatlens.onrender.com` (or your chosen name).

---

## Option 2: 1-Click Deployment on Railway

Railway auto-detects `Dockerfile` and `railway.json`.

### Step 1: Log in to Railway
1. Go to [https://railway.app](https://railway.app) and sign in with GitHub.

### Step 2: Deploy from GitHub Repo
1. Click **New Project** $\rightarrow$ **Deploy from GitHub repo**.
2. Select `SaiNikhil6305/Threatlens`.
3. Railway automatically detects the `Dockerfile` and triggers the deployment.

### Step 3: Generate Public Domain
1. In the project dashboard, click on your service $\rightarrow$ **Settings** $\rightarrow$ **Networking**.
2. Click **Generate Domain**.
3. Your application is live instantly!

---

## Local Docker Deployment (Optional)

To test the production container locally on your own machine:

```powershell
# From the project root
docker build -t threatlens .
docker run -p 8000:8000 threatlens
```
Then navigate to `http://localhost:8000`.
