# Azure AD Graph Visualizer

Interactive visualization tool for exploring Azure Active Directory group hierarchies. Built with React (Vite) and FastAPI.

![Azure AD Viz](https://img.shields.io/badge/React-18.3-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)

## Features

- 🔍 **Search Groups**: Real-time search for Azure AD groups
- 🌐 **Interactive Graph**: Force-directed graph visualization with zoom/pan
- 👥 **Hierarchy Exploration**: View parent groups, child groups, and users
- 📊 **Node Details**: Click any node to see detailed information
- 🎨 **Modern UI**: Built with Tailwind CSS and Lucide icons
- 🔄 **Mock Mode**: Test without Azure credentials

## Project Structure

```
ADGraphViz/
├── src/                    # React frontend
│   ├── App.jsx            # Main application component
│   ├── main.jsx           # React entry point
│   ├── index.css          # Global styles
│   └── App.css            # Component styles
├── backend/               # Python FastAPI backend
│   ├── main.py           # API server
│   ├── requirements.txt  # Python dependencies
│   └── .env.example      # Environment template
├── vite.config.js        # Vite configuration
├── package.json          # Node dependencies
└── README.md             # This file
```

## Quick Start

### Prerequisites

- **Node.js** 18+ and npm
- **Python** 3.9+
- **Azure AD App Registration** (for production mode)

### Frontend Setup

```powershell
# Install dependencies
npm install

# Start development server
npm run dev
```

The app will be available at `http://localhost:5173`

### Backend Setup (Optional - for Real Azure AD Integration)

```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Configure Azure credentials
cp .env.example .env
# Edit .env with your Azure AD credentials

# Start API server
python main.py
```

The API will be available at `http://localhost:8000`

## Configuration

### Mock Mode (Default)

The application runs in **mock mode** by default, generating sample data. Perfect for testing without Azure credentials.

To switch modes, edit `src/App.jsx`:

```javascript
const USE_MOCK_DATA = true;  // Set to false for real Azure AD
```

### Production Mode (Azure AD)

1. **Create an Azure AD App Registration:**
   - Go to [Azure Portal](https://portal.azure.com) → Azure Active Directory → App registrations
   - Create a new registration
   - Add API permissions: `Group.Read.All`, `User.Read.All`
   - Create a client secret

2. **Configure Backend:**
   ```powershell
   cd backend
   cp .env.example .env
   ```

   Edit `.env`:
   ```env
   AZURE_TENANT_ID=your-tenant-id
   AZURE_CLIENT_ID=your-client-id
   AZURE_CLIENT_SECRET=your-client-secret
   ```

3. **Update Frontend:**
   ```javascript
   // In src/App.jsx
   const USE_MOCK_DATA = false;
   ```

4. **Start both servers:**
   ```powershell
   # Terminal 1 - Backend
   cd backend
   python main.py

   # Terminal 2 - Frontend
   npm run dev
   ```

## Features Explained

### Force-Directed Graph

- **Pan**: Click and drag the background
- **Zoom**: Scroll wheel to zoom in/out
- **Node Click**: Click any node to view details
- **Auto-Layout**: Nodes automatically arrange using physics simulation

### Node Types

- 🔵 **Root Node** (Indigo): The currently selected group
- 🔵 **Group Node** (Blue): Child groups or parent groups
- 🟢 **User Node** (Green): Individual users

### Search & Navigation

1. Type in the search box (minimum 2 characters)
2. Select a group from dropdown
3. Graph loads showing:
   - Parent groups (groups this group belongs to)
   - The selected group (center)
   - Child groups (nested groups)
   - Direct users (members)

## API Endpoints

### `GET /api/groups/search?q={query}`

Search for groups by display name.

**Response:**
```json
[
  {
    "id": "group-guid",
    "displayName": "Engineering Team",
    "description": "Engineering staff"
  }
]
```

### `GET /api/groups/hierarchy/{group_id}`

Get the hierarchy around a specific group.

**Response:**
```json
{
  "nodes": [
    {
      "id": "guid",
      "type": "root|group|user",
      "displayName": "Name",
      "data": { ... }
    }
  ],
  "edges": [
    {
      "source": "parent-id",
      "target": "child-id",
      "type": "contains"
    }
  ]
}
```

## Troubleshooting

### Vite Build Error (lightningcss)

If you see `Cannot find module 'lightningcss.win32-x64-msvc.node'`:

**Solution**: Already fixed in `vite.config.js` by forcing PostCSS transformer:
```javascript
css: {
  transformer: 'postcss',
}
```

### Python Backend Issues

**Import Errors:**
```powershell
pip install -r requirements.txt
```

**Authentication Errors:**
- Verify your Azure credentials in `.env`
- Ensure the app registration has correct permissions
- Grant admin consent for the API permissions

### CORS Errors

The backend is configured to accept all origins in development. For production, update:

```python
allow_origins=["https://your-frontend-domain.com"]
```

## Development

### Building for Production

```powershell
npm run build
```

Output will be in `dist/` directory.

### Customization

**Graph Physics:** Edit force simulation parameters in `ForceGraph` component:
```javascript
const k = 0.05;        // Attraction strength
const repulsion = 4000; // Repulsion force
n.vx *= 0.8;           // Damping (friction)
```

**Styling:** Uses Tailwind CSS utility classes. Modify in JSX or add custom styles to `App.css`.

## Technologies

- **Frontend**: React 18, Vite, Tailwind CSS 4, Lucide React
- **Backend**: FastAPI, MSAL, Microsoft Graph API
- **Visualization**: Custom SVG force-directed graph

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push and create a Pull Request

## Support

For issues or questions:
- Check the [Troubleshooting](#troubleshooting) section
- Review Azure AD app registration setup
- Ensure all dependencies are installed

---

**Built with ❤️ for Azure AD administrators**
