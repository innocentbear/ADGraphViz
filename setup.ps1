# Setup Script for ADGraphViz

Write-Host "=== Azure AD Graph Visualizer Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check Node.js
Write-Host "Checking Node.js installation..." -ForegroundColor Yellow
$nodeVersion = $null
try {
    $nodeVersion = node --version 2>$null
    if ($nodeVersion) {
        Write-Host "✓ Node.js found: $nodeVersion" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ Node.js not found" -ForegroundColor Red
    Write-Host "  Please install Node.js 18+ from https://nodejs.org/" -ForegroundColor Yellow
    Write-Host "  After installation, restart your terminal and run this script again." -ForegroundColor Yellow
    exit 1
}

# Check npm
Write-Host "Checking npm..." -ForegroundColor Yellow
$npmVersion = $null
try {
    $npmVersion = npm --version 2>$null
    if ($npmVersion) {
        Write-Host "✓ npm found: $npmVersion" -ForegroundColor Green
    }
} catch {
    Write-Host "✗ npm not found (should come with Node.js)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Frontend dependencies installed successfully!" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to install frontend dependencies" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Setup Complete! ===" -ForegroundColor Green
Write-Host ""
Write-Host "To start the development server:" -ForegroundColor Cyan
Write-Host "  npm run dev" -ForegroundColor White
Write-Host ""
Write-Host "The app will run in MOCK MODE by default (no Azure credentials needed)" -ForegroundColor Yellow
Write-Host ""
Write-Host "For production mode with Azure AD:" -ForegroundColor Cyan
Write-Host "  1. Set up Python backend (see README.md)" -ForegroundColor White
Write-Host "  2. Configure Azure credentials in backend/.env" -ForegroundColor White
Write-Host "  3. Change USE_MOCK_DATA to false in src/App.jsx" -ForegroundColor White
Write-Host ""
