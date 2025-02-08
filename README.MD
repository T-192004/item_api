# RESTful API with Node.js, Express, and PostgreSQL

## Overview
This project is a RESTful API built using **Node.js**, **Express**, and **PostgreSQL**. It includes CRUD operations for managing items, user authentication with JWT, rate-limiting for security, and asynchronous file handling for logging metadata.

## Features
- User registration and authentication with JWT
- CRUD operations for managing items in a PostgreSQL database
- Rate limiting to prevent excessive requests
- Asynchronous file handling for logging API activity
- Secure environment variable handling with dotenv
- Deployment on **Render** with PostgreSQL database integration

## Technologies Used
- **Node.js**
- **Express.js**
- **PostgreSQL**
- **pg (PostgreSQL Client)**
- **bcryptjs** for password hashing
- **jsonwebtoken** for authentication
- **express-rate-limit** for API rate limiting
- **fs.promises** for asynchronous file handling
- **dotenv** for environment variable management

## Installation & Setup
### 1. Clone the repository:
```sh
git clone https://github.com/T-192004/item_api
cd item_api
```

### 2. Install dependencies:
```sh
npm install
```

### 3. Set up environment variables:
Create a `.env` file in the root directory and configure it as follows:
```env
PORT=5000
DATABASE_URL=your_postgresql_database_url
JWT_SECRET=your_secret_key
```

### 4. Run database migrations:
Ensure your PostgreSQL database is running, then execute:
```sh
node server.js
```
This will automatically create the necessary tables if they don't exist.

### 5. Start the application:
```sh
npm start
```
The server will run on `http://localhost:5000`

---

## API Endpoints
### Authentication
#### **User Registration**
**POST /register**
```json
{
  "username": "exampleUser",
  "password": "securePassword",
  "email": "user@example.com"
}
```
_Response:_
```json
{
  "message": "User registered successfully"
}
```

#### **User Login**
**POST /login**
```json
{
  "username": "exampleUser",
  "password": "securePassword"
}
```
_Response:_
```json
{
  "token": "your_jwt_token"
}
```
Use this token for authentication in protected routes.

---
### Items Management (Protected Routes)
Include the JWT token in the `Authorization` header as `Bearer <token>`.

#### **Get All Items**
**GET /api/items**
_Response:_
```json
[
  { "id": 1, "name": "Item 1", "description": "Description 1", "created_at": "timestamp" }
]
```

#### **Create an Item**
**POST /api/items**
```json
{
  "name": "New Item",
  "description": "Item description"
}
```
_Response:_
```json
{
  "id": 2, "name": "New Item", "description": "Item description", "created_at": "timestamp"
}
```

#### **Update an Item**
**PUT /api/items/:id**
```json
{
  "name": "Updated Item",
  "description": "Updated description"
}
```
_Response:_
```json
{
  "message": "Item updated successfully"
}
```

#### **Delete an Item**
**DELETE /api/items/:id**
_Response:_
```json
{
  "message": "Item deleted successfully"
}
```

---

## Rate Limiting
Each IP is limited to **100 requests per 15 minutes**. Exceeding this limit will result in:
```json
{
  "message": "Rate limit exceeded, try again later."
}
```

## Logging
Every new item created is logged in `logs.json` with a timestamp.

---

## Deployment on Render
### 1. Create a PostgreSQL Database on Render
- Go to [Render](https://render.com)
- Create a new PostgreSQL database
- Copy the database URL and set it as `DATABASE_URL` in your environment variables

### 2. Deploy the Application
- Push your code to GitHub
- On Render, create a new **Web Service** and link your GitHub repository
- Set the environment variables
- Deploy the application

## License
This project is open-source under the MIT License.

