# Role-Based Access Control (RBAC) API

A secure Node.js REST API implementing JWT-based authentication and role-based access control, fully containerized with Docker.

## Features

- JWT Authentication with secure password hashing
- Role-Based Access Control (RBAC)
- MongoDB database with Mongoose ODM
- Docker & Docker Compose setup
- Automated database seeding
- Swagger API Documentation
- Comprehensive test suite

## Tech Stack

- Node.js + Express
- MongoDB + Mongoose
- JWT + bcrypt
- Docker & Docker Compose
- Jest + Supertest
- Swagger UI

## Roles & Permissions

| Role    | Permissions                                              |
|---------|----------------------------------------------------------|
| admin   | Full access (all operations)                             |
| manager | users:read, projects:read, projects:write                |
| viewer  | projects:read                                            |

## API Endpoints

### Authentication
- `POST /auth/login` - Login and receive JWT token

### Users
- `GET /users` - List all users (admin, manager)
- `POST /users` - Create new user (admin only)

### Projects
- `GET /projects` - List all projects (admin, manager, viewer)
- `GET /projects/:id` - Get project by ID (admin, manager, viewer)
- `POST /projects` - Create project (admin, manager)
- `PUT /projects/:id` - Update project (admin, manager)
- `DELETE /projects/:id` - Delete project (admin only)

## Quick Start

### Prerequisites
- **For Docker**: Docker & Docker Compose
- **For Local**: Node.js (v18+) & MongoDB installed locally

### Option 1: Running with Docker (Recommended - Easiest)

**No need to install Node.js or MongoDB locally!**

1. **Clone the repository**
```bash
git clone
cd rbac-api
```

2. **Create `.env` file**
```bash
# Create .env file with these contents:
PORT=3000
NODE_ENV=production
MONGODB_URI=mongodb://mongodb:27017/rbac_db
JWT_SECRET=your-super-secret-jwt-key
JWT_EXPIRES_IN=24h
```

3. **Running Docker**
```bash
docker compose up --build
```

**Wait for these messages in the logs:**
```
rbac-mongodb     | Waiting for connections
rbac-api         | MongoDB connected successfully
rbac-api         | Database seeded successfully
rbac-api         | Server running on port 3000
```

4. **Access the API**
- API: http://localhost:3000
- Swagger Docs: http://localhost:3000/api-docs
- Health Check: http://localhost:3000/health

**Useful Docker Commands:**
```bash
# Stop containers (keeps data)
docker compose down

# Stop and remove all data
docker compose down -v

# View logs
docker compose logs -f api

# Restart containers
docker compose restart

# Run in background (detached mode)
docker compose up -d --build

# Check container status
docker compose ps

# Run tests inside container
docker compose exec api npm test
```

### Option 2: Running Locally (without Docker)

**Prerequisites:**
- Node.js v18 or higher
- MongoDB running locally or MongoDB Atlas

**Steps:**

1. **Clone and setup**
```bash
git clone <repository-url>
cd rbac-api
```

3. **Install dependencies**
```bash
npm install
```

4. **Create `.env` file for local development**
```bash
# Create .env with local MongoDB URI
PORT=3000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/rbac_db
JWT_SECRET=your-super-secret-jwt-key-change-in-production
JWT_EXPIRES_IN=24h
```

5. **Start MongoDB** (if installed locally)
```bash
# Windows
net start MongoDB

6. **Start the application**
```bash
npm start

The API will be available at `http://localhost:3000`


### Seeded User Credentials

The application automatically seeds the following users:

| Email                  | Password     | Role    |
|------------------------|--------------|---------|
| admin@example.com      | admin123     | admin   |
| manager@example.com    | manager123   | manager |
| viewer@example.com     | viewer123    | viewer  |

## API Documentation

- **Swagger UI**: http://localhost:3000/api-docs
- **Postman Collection**: Import `postman_collection.json`

## Example API Calls

### 1. Login
```bash
curl --location 'http://localhost:3000/auth/login' \
--header 'Content-Type: application/json' \
--data-raw '{"email":"admin@example.com","password":"admin123"}'
```

### 2. Get All Users (Admin/Manager)
```bash
curl -X GET http://localhost:3000/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 3. Create Project (Admin/Manager)
```bash
curl -X POST http://localhost:3000/projects \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "New Project",
    "description": "Project description"
  }'
```

### 4. Get All Projects (All Roles)
```bash
curl -X GET http://localhost:3000/projects \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Delete Project (Admin Only)
```bash
curl -X DELETE http://localhost:3000/projects/PROJECT_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage report
npm test:coverage

# Run tests in watch mode (for development)
npm test:watch
```




