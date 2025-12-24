# Quick Start Guide

## Prerequisites Check

Before running the application, ensure you have:

### Required
- **Node.js 18+**: Download from [nodejs.org](https://nodejs.org/)
  - Verify: `node --version`
  - Verify: `npm --version`

### Optional (for Azure AD integration)
- **Python 3.9+**: Download from [python.org](https://python.org/)
  - Verify: `python --version`

## Installation Steps

### Option 1: Automated Setup (Windows)

```powershell
.\setup.ps1
```

### Option 2: Manual Setup

1. **Install frontend dependencies:**
   ```powershell
   npm install
   ```

2. **Start development server:**
   ```powershell
   npm run dev
   ```

3. **Open browser:**
   - Navigate to `http://localhost:5173`
   - App runs in **mock mode** by default (no Azure credentials needed)

## Testing Mock Mode

The application includes sample data for testing:

1. Start the dev server: `npm run dev`
2. Open `http://localhost:5173`
3. In the search box, type: `all` or `eng` or `finance`
4. Click a group from the dropdown
5. Explore the interactive graph

## Setting Up Azure AD Integration

Only needed if you want to connect to real Azure AD data.

### 1. Python Backend Setup

```powershell
# Navigate to backend folder
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 2. Azure AD App Registration

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to: **Azure Active Directory** → **App registrations** → **New registration**
3. Name: `ADGraphViz` (or your choice)
4. Supported account types: **Single tenant**
5. Click **Register**

6. **API Permissions:**
   - Click **API permissions** → **Add a permission**
   - Select **Microsoft Graph** → **Application permissions**
   - Add: `Group.Read.All`, `User.Read.All`, `Directory.Read.All`
   - Click **Grant admin consent** (requires admin)

7. **Create Client Secret:**
   - Click **Certificates & secrets** → **New client secret**
   - Description: `ADGraphViz Secret`
   - Expires: Choose duration
   - Click **Add**
   - **Copy the secret value** (you won't see it again!)

8. **Copy Configuration Values:**
   - From **Overview** page, copy:
     - **Application (client) ID**
     - **Directory (tenant) ID**

### 3. Configure Backend

```powershell
cd backend
cp .env.example .env
```

Edit `.env` file with your values:
```env
AZURE_TENANT_ID=your-tenant-id-from-step-8
AZURE_CLIENT_ID=your-client-id-from-step-8
AZURE_CLIENT_SECRET=your-secret-from-step-7
```

### 4. Update Frontend Configuration

Edit `src/App.jsx` (line 17):
```javascript
const USE_MOCK_DATA = false;  // Change from true to false
```

### 5. Start Both Servers

**Terminal 1 - Backend:**
```powershell
cd backend
.\venv\Scripts\Activate.ps1
python main.py
```
Backend runs at: `http://localhost:8000`

**Terminal 2 - Frontend:**
```powershell
npm run dev
```
Frontend runs at: `http://localhost:5173`

## Verification

### Mock Mode
- Search should return: "All Employees", "Engineering Leads", "Finance Dept", "IT Admins"
- Clicking a group shows a generated hierarchy

### Production Mode
- Search should return real Azure AD groups
- Clicking a group shows actual members and parent groups
- Check backend terminal for API logs

## Common Issues

### Node.js not found
```
Solution: Install Node.js from nodejs.org and restart terminal
```

### npm install fails
```
Solution: 
1. Delete node_modules folder
2. Delete package-lock.json
3. Run: npm install
```

### Vite lightningcss error
```
Solution: Already fixed! The vite.config.js forces PostCSS transformer
```

### Python backend import errors
```
Solution: Ensure virtual environment is activated and run:
pip install -r requirements.txt
```

### Azure authentication fails
```
Solution: 
1. Verify .env values are correct
2. Ensure app has API permissions
3. Grant admin consent in Azure Portal
4. Check client secret hasn't expired
```

### CORS errors in browser
```
Solution: Ensure backend is running on localhost:8000
The backend already has CORS enabled for development
```

## Development Workflow

```powershell
# 1. Start frontend (always needed)
npm run dev

# 2. Start backend (only if using Azure AD)
cd backend
.\venv\Scripts\Activate.ps1
python main.py
```

## Next Steps

- ✅ Search for groups
- ✅ Click nodes to view details
- ✅ Zoom and pan the graph
- ✅ Click "Focus Visualization Here" on group nodes to explore deeper

---

**Tip**: Start with mock mode to familiarize yourself with the UI before connecting to Azure AD.
