# Docker Setup Guide for Azure AD Graph Visualizer

## Quick Start with Docker Compose

The easiest way to run the entire application:

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

The application will be available at:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Documentation**: http://localhost:8000/docs

## Building Individual Images

### Backend Image

```bash
# Build
docker build -f Dockerfile.backend -t adgraphviz-backend:latest .

# Run
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  -e AZURE_TENANT_ID=your_tenant_id \
  -e AZURE_CLIENT_ID=your_client_id \
  -e AZURE_CLIENT_SECRET=your_client_secret \
  adgraphviz-backend:latest

# View logs
docker logs -f adgraphviz-backend

# Stop
docker stop adgraphviz-backend
docker rm adgraphviz-backend
```

### Frontend Image

```bash
# Build
docker build -f Dockerfile.frontend -t adgraphviz-frontend:latest .

# Run
docker run -d \
  --name adgraphviz-frontend \
  -p 3000:3000 \
  -e VITE_API_BASE_URL=http://localhost:8000/api \
  adgraphviz-frontend:latest

# View logs
docker logs -f adgraphviz-frontend

# Stop
docker stop adgraphviz-frontend
docker rm adgraphviz-frontend
```

## GitHub Container Registry (GHCR)

The GitHub Actions workflow automatically builds and pushes images to GHCR on:
- **Push to main/develop** - Builds with `latest` tag and git SHA
- **Tag push** (e.g., `v1.0.0`) - Builds with semantic version tags
- **Pull requests** - Only builds, doesn't push

### Using GHCR Images

```bash
# Login to GHCR (first time only)
echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u ${{ github.actor }} --password-stdin

# Pull images
docker pull ghcr.io/innocentbear/adgraphviz-backend:latest
docker pull ghcr.io/innocentbear/adgraphviz-frontend:latest

# Run
docker run -d \
  --name adgraphviz-backend \
  -p 8000:8000 \
  -e AZURE_TENANT_ID=your_tenant_id \
  -e AZURE_CLIENT_ID=your_client_id \
  -e AZURE_CLIENT_SECRET=your_client_secret \
  ghcr.io/innocentbear/adgraphviz-backend:latest

docker run -d \
  --name adgraphviz-frontend \
  -p 3000:3000 \
  ghcr.io/innocentbear/adgraphviz-frontend:latest
```

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
