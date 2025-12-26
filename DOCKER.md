# Docker Setup Guide for Azure AD Graph Visualizer

## Prerequisites

- Docker Desktop (v24+) installed
- Docker Compose (v2+) installed
- Azure AD credentials (for running with real data)

## Quick Start with Docker Compose

The easiest way to run the entire application:

```bash
# 1. Create .env file with Azure credentials
cp backend/.env.example backend/.env
# Edit backend/.env with your Azure credentials

# 2. Build and start all services
docker-compose up -d

# 3. View logs (watch for startup messages)
docker-compose logs -f

# 4. Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/docs

# 5. Stop services
docker-compose down
```

## Building Individual Images

### Backend Image

```bash
# Build with multi-stage optimization
docker build -f Dockerfile.backend -t adgraphviz-backend:latest .

# Run with environment variables
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  --env-file backend/.env \
  adgraphviz-backend:latest

# View logs
docker logs -f adgraphviz-backend

# Access API docs
# Open: http://localhost:8000/docs

# Stop container
docker stop adgraphviz-backend
docker rm adgraphviz-backend
```

### Frontend Image

```bash
# Build with multi-stage optimization
docker build -f Dockerfile.frontend -t adgraphviz-frontend:latest .

# Run with API URL configuration
docker run -d \
  --name adgraphviz-frontend \
  -p 3000:3000 \
  -e VITE_API_BASE_URL=http://localhost:8000/api \
  adgraphviz-frontend:latest

# View logs
docker logs -f adgraphviz-frontend

# Access application
# Open: http://localhost:3000

# Stop container
docker stop adgraphviz-frontend
docker rm adgraphviz-frontend
```

## Docker Image Specifications

### Backend Image (`Dockerfile.backend`)
- **Base Image**: `python:3.11-slim`
- **Multi-stage**: Yes (reduces final size ~60%)
- **Security**: Non-root user (appuser)
- **Health Check**: Enabled (curl to /docs)
- **Size**: ~300MB (optimized)
- **Port**: 8000

**Features**:
- Virtual environment isolation
- Minimal runtime dependencies
- Security scanning with Trivy
- Cache optimization

### Frontend Image (`Dockerfile.frontend`)
- **Base Image**: `node:20-alpine` (builder) → `node:20-alpine` (runtime)
- **Multi-stage**: Yes (reduces final size ~70%)
- **Security**: Non-root user (appuser)
- **Health Check**: Enabled (wget check)
- **Size**: ~200MB (optimized)
- **Port**: 3000
- **Server**: `serve` (lightweight)

**Features**:
- Production build optimization
- Code minification
- Tree-shaking
- Cache optimization

## GitHub Container Registry (GHCR)

### Automatic Builds

GitHub Actions automatically builds and pushes images to GHCR when:
- **Push to main/develop**: Creates tags with `latest` and git SHA
- **Tag push** (e.g., `v1.0.0`): Creates semantic version tags
- **Pull requests**: Builds only (doesn't push)

### Workflow File

Location: `.github/workflows/docker-build-push.yml`

**Features**:
- Parallel builds (frontend + backend)
- Docker BuildKit cache optimization
- Trivy security scanning
- SARIF report upload to GitHub Security tab

### Using GHCR Images

```bash
# 1. Login to GHCR (one-time setup)
export CR_PAT=your_github_token
echo $CR_PAT | docker login ghcr.io -u YOUR_USERNAME --password-stdin

# 2. Pull latest images
docker pull ghcr.io/innocentbear/adgraphviz-backend:latest
docker pull ghcr.io/innocentbear/adgraphviz-frontend:latest

# 3. Run with docker-compose using GHCR images
docker-compose -f docker-compose.prod.yml up -d

# 4. Or run individually
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  --env-file backend/.env \
  ghcr.io/innocentbear/adgraphviz-backend:latest

docker run -d \
  --name adgraphviz-frontend \
  -p 3000:3000 \
  -e VITE_API_BASE_URL=http://backend:8000/api \
  ghcr.io/innocentbear/adgraphviz-frontend:latest
```

### Image Tagging Strategy

Tags follow this pattern:
```
ghcr.io/innocentbear/adgraphviz-backend:VARIANT-TAG
```

**Examples**:
- `backend-latest` - Latest main branch build
- `backend-main` - Main branch builds
- `backend-develop` - Develop branch builds
- `backend-v1.0.0` - Release version
- `backend-abc123de` - Git SHA (commit-specific)

## Common Docker Commands

```bash
# View image sizes
docker images adgraphviz*

# Inspect image
docker inspect ghcr.io/innocentbear/adgraphviz-backend:latest

# Run with resource limits
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  --memory 512m \
  --cpus 1 \
  adgraphviz-backend:latest

# Clean up
docker system prune -a  # Remove unused images/containers
docker image prune       # Remove dangling images
docker container prune   # Remove stopped containers
```

## Troubleshooting

### Image build fails with npm ci

**Problem**: `npm ci` fails in Dockerfile.frontend
```
ERROR: failed to solve: process "/bin/sh -c npm ci" did not complete successfully
```

**Solution**: Use `npm install` fallback (already in Dockerfile)
```dockerfile
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
```

### Container exits immediately

**Problem**: Container starts but exits
```bash
docker logs adgraphviz-backend
# Check output for errors
```

**Solution**: Ensure environment variables are set
```bash
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  --env-file backend/.env \
  adgraphviz-backend:latest
```

### Port already in use

**Problem**: `bind: address already in use`

**Solution**: Use different ports
```bash
docker run -d \
  --name adgraphviz-backend \
  -p 8001:8000 \  # Host:Container
  adgraphviz-backend:latest
```

Or kill existing container:
```bash
docker ps  # Find container ID
docker stop <CONTAINER_ID>
docker rm <CONTAINER_ID>
```

### Health check failing

**Problem**: Container unhealthy after startup

**Solution**: Check logs and wait longer
```bash
docker logs adgraphviz-backend
docker inspect adgraphviz-backend  # See health status

# Increase start_period in docker-compose.yml
healthcheck:
  start_period: 30s  # Increase timeout
```

## Security Considerations

### Best Practices Applied

✅ **Non-root users**: Images run as `appuser` (UID 1000)
✅ **Multi-stage builds**: Smaller attack surface
✅ **Minimal base images**: Reduced vulnerabilities
✅ **Health checks**: Automatic restart on failure
✅ **No secrets in images**: Use environment variables
✅ **Read-only root**: Can be enabled with `--read-only`
✅ **Resource limits**: Set memory/CPU limits
✅ **Scan with Trivy**: Security scanning in CI/CD

### Running with Security Options

```bash
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  --read-only \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --env-file backend/.env \
  adgraphviz-backend:latest
```

## Performance Tips

1. **Enable BuildKit**:
   ```bash
   export DOCKER_BUILDKIT=1
   ```

2. **Use .dockerignore**: Reduces context size (already configured)

3. **Layer caching**: Dockerfile ordered for optimal caching

4. **Multi-stage builds**: Reduces final image size by 60-70%

5. **Alpine base**: Smaller than standard images

## Docker Compose with GHCR Images

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  backend:
    image: ghcr.io/innocentbear/adgraphviz-backend:latest
    container_name: adgraphviz-backend
    ports:
      - "8000:8000"
    environment:
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
    networks:
      - adgraphviz-network
    healthcheck:
      test: ["CMD", "python", "-c", "import requests; requests.get('http://localhost:8000/docs')"]
      interval: 30s
      timeout: 10s
      retries: 3

  frontend:
    image: ghcr.io/innocentbear/adgraphviz-frontend:latest
    container_name: adgraphviz-frontend
    ports:
      - "3000:3000"
    networks:
      - adgraphviz-network
    depends_on:
      backend:
        condition: service_healthy
    environment:
      - VITE_API_BASE_URL=http://backend:8000/api

networks:
  adgraphviz-network:
    driver: bridge
```

Then run:
```bash
docker-compose -f docker-compose.prod.yml up -d
```

## Environment Variables

### Backend (.env or docker-compose)
```
AZURE_TENANT_ID=your_azure_tenant_id
AZURE_CLIENT_ID=your_azure_app_id
AZURE_CLIENT_SECRET=your_azure_app_secret
```

### Frontend (docker-compose)
```
VITE_API_BASE_URL=http://backend:8000/api  # For docker
VITE_API_BASE_URL=http://localhost:8000/api  # For localhost
```

## Image Specifications

### Backend Image
- **Base**: python:3.11-slim
- **Size**: ~150MB
- **Ports**: 8000
- **Health Check**: HTTP check to /docs endpoint

### Frontend Image
- **Base**: node:20-alpine (production) + alpine (build)
- **Size**: ~100MB (alpine-based)
- **Ports**: 3000
- **Health Check**: wget check to http://localhost:3000

## Security Features

1. **Multi-stage builds** - Reduces final image size and attack surface
2. **Non-root user** - Containers run as `appuser` (UID 1000)
3. **Health checks** - Built-in readiness probes
4. **Security scanning** - Trivy scans images for vulnerabilities
5. **.dockerignore** - Excludes unnecessary files from build context

## Kubernetes Deployment

Example manifests for Kubernetes:

```yaml
# backend-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: adgraphviz-backend
spec:
  replicas: 2
  selector:
    matchLabels:
      app: adgraphviz-backend
  template:
    metadata:
      labels:
        app: adgraphviz-backend
    spec:
      containers:
      - name: backend
        image: ghcr.io/innocentbear/adgraphviz-backend:latest
        ports:
        - containerPort: 8000
        env:
        - name: AZURE_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: azure-creds
              key: tenant-id
        - name: AZURE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: azure-creds
              key: client-id
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: azure-creds
              key: client-secret
        livenessProbe:
          httpGet:
            path: /docs
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /docs
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## Troubleshooting

### Backend fails to start
```bash
# Check logs
docker logs adgraphviz-backend

# Verify environment variables
docker exec adgraphviz-backend env | grep AZURE

# Test API endpoint
curl http://localhost:8000/docs
```

### Frontend can't connect to backend
```bash
# Check network connectivity
docker exec adgraphviz-frontend ping backend

# Verify API URL
docker exec adgraphviz-frontend env | grep VITE_API
```

### Image build fails
```bash
# Clean build (no cache)
docker build --no-cache -f Dockerfile.backend -t adgraphviz-backend:latest .

# Check disk space
docker system df
docker system prune -a
```

## References

- [Docker Best Practices](https://docs.docker.com/develop/dev-best-practices/)
- [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
