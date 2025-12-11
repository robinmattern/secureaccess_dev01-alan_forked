# A03 Register CORS - Dynamic API Key Management
<br/>

<details>
<summary><b>A. Package.json Configuration</b></summary>

### 1. Root Level - `./package.json`
```json
{
  "scripts": {
    "start:c01": "live-server client/c01_client-first-app --port=57301 --no-browser",
    "start:s01": "nodemon server/s01_server-first-api/server.js --port=57351",
    "start:c03": "live-server client/c03_register-cors-app --port=57303 --no-browser",    
    "start:s03": "nodemon server/s03_register-cors-api/server.mjs"
  }
}
```
**Purpose:** Run any app from workspace root

### 2. Client Level - `./client/package.json`
```json
{
  "scripts": {
    "start:c01": "live-server c01_client-first-app --port=57301 --no-browser",
    "start:c03": "live-server c03_register-cors-app --port=57303 --no-browser"
  },
  "devDependencies": {
    "live-server": "^1.2.2"
  }
}
```
**Purpose:** Run client apps with shared dependencies

### 3. Individual Client App - `./client/c03_register-cors-app/package.json`
**Not needed** - dependencies managed at parent level

### 4. Server Level - `./server/package.json`
```json
{
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcrypt": "^6.0.0",
    "jsonwebtoken": "^9.0.2"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```
**Purpose:** Shared server dependencies

### 5. Individual Server API - `./server/s03_register-cors-api/package.json`
**Not needed** - dependencies managed at parent level

</details>

<details>
<summary><b>B. Server API Installation & Startup with NodeJS</b></summary>

1. Install Node Express and CORS modules
```bash
# Open terminal in ./server
cd server
npm install
```
2. Start the API Server 
```bash
# Open terminal in ./server
cd server
npm run start:s03
```
**Result:** Server runs on `http://localhost:57353`

</details>

<details>
<summary><b>C. Client App Installation & Startup with Five-Server</b></summary>

### Install Extension
- Search for Extension: **five server**
- Install: **Live Server (Five Server)**

### Start First App (c03)
1. Create `.fiveserverrc` in workspace root:
```json
{ "port": 57303 }
```
2. Right-click `./client/c03_register-cors-app` 
3. Select **"Run with Five-Server (root)"**
4. Opens: `http://127.0.0.1:57303/`

### Start Second App (c01)
1. **Restart VSCode** or run **"Developer: Reload Window"**
2. Edit `.fiveserverrc` in workspace root:
```json
{ "port": 57301 }
```
3. Right-click `./client/c01_client-first-app`
4. Select **"Run with Five-Server (root)"**
5. Opens: `http://127.0.0.1:57301/`

**Note:** Five-Server can only run one app at a time via extension

</details>

<details>
<summary><b>D. How the Apps Work</b></summary>

### Port Assignment Pattern
- **57301:** Client App 01
- **57303:** Client App 03  
- **57351:** Server API 01
- **57353:** Server API 53

Format: `573XX` (Project 57, Dev 3, App XX)

### C03 Client App (Port 57303)
- **Purpose:** Web interface for API key registration
- **Features:**
  - Register new users with API keys
  - Set allowed origins and APIs per user
  - View all registered users
  - Delete users
- **API Calls:** Makes requests to `http://localhost:57353/api`

### S03 Server API (Port 57353)
- **Purpose:** Backend service for managing API keys and CORS
- **Endpoints:**
  - `POST /api/register` - Register new user
  - `GET /api/users` - List all users
  - `PUT /api/users/:userId/origins` - Update user origins
  - `DELETE /api/users/:userId` - Delete user
- **Storage:** Persists data to `api-registry.json`
- **CORS:** Allows requests from `http://localhost:57303`

</details>

<details>
<summary><b>E. Testing the Registration App</b></summary>

### 1. Start Both Services
```bash
# Terminal 1 - Start server
cd server
npm run start:s03

# Terminal 2 - Start client  
cd client
npm run start:c03
```

### 2. Register a User
1. Open `http://localhost:57303`
2. Fill form:
   - **User ID:** `testuser`
   - **Allowed Origins:** `https://myapp.com`
   - **Allowed APIs:** `APIapp1`
3. Click **"Register User"**
4. Copy the generated API key

### 3. Test API Access
```bash
curl -X GET http://localhost:57353/api/users \
  -H "Origin: https://myapp.com" \
  -H "X-API-Key: key_abc123"
```

### 4. Verify CORS
- Valid origin: Request succeeds
- Invalid origin: CORS error
- Missing API key: Access denied

</details>

