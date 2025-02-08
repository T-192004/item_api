# RESTful API with Node.js, Express, and PostgreSQL

## Project Overview
This project is a **RESTful API** built using **Node.js** and **Express.js**, with **PostgreSQL** as the database. It implements **CRUD operations**, **rate limiting**, **asynchronous file handling**, and **JWT-based authentication**.

### Features:
- **User Authentication** (Register & Login with JWT authentication)
- **CRUD operations** for managing items
- **Rate limiting** to prevent API abuse
- **Logging with asynchronous file handling**
- **Error handling** for robust performance
- **Deployment on Render**

## Deployed API URL
The API is deployed on **Render** and can be accessed at:
🔗 [https://item-api-9737.onrender.com](https://item-api-9737.onrender.com)

## Technologies Used
- **Node.js** - Backend runtime environment
- **Express.js** - Web framework for API handling
- **PostgreSQL** - Relational database
- **jsonwebtoken (JWT)** - Authentication
- **bcrypt.js** - Secure password hashing
- **fs.promises** - Asynchronous file handling
- **express-rate-limit** - Rate limiting middleware
- **dotenv** - Environment variable management

## Project Setup
### 1. Clone the Repository
```bash
git clone https://github.com/your-username/your-repository.git
cd your-repository
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment Variables
Create a `.env` file and add the following environment variables:
```env
PORT=5000
DATABASE_URL=your_postgresql_database_url
JWT_SECRET=your_secret_key
```

### 4. Run the Application
```bash
npm start
```

## API Endpoints
### **User Authentication**
#### Register a User
```
POST /register
```
**Request Body:**
```json
{
  "username": "testuser",
  "password": "securepassword",
  "email": "test@example.com"
}
```

#### Login and Get JWT Token
```
POST /login
```
**Request Body:**
```json
{
  "username": "testuser",
  "password": "securepassword"
}
```
**Response:**
```json
{
  "token": "your_generated_jwt_token"
}
```

### **CRUD Operations (Protected Routes)**
Authorization: Add JWT token in `Authorization` header as `Bearer <token>`.

#### Create an Item
```
POST /api/items
```
**Request Body:**
```json
{
  "name": "Laptop",
  "description": "High-performance laptop"
}
```

#### Get All Items
```
GET /api/items
```

#### Get Item by ID
```
GET /api/items/:id
```

#### Update an Item
```
PUT /api/items/:id
```
**Request Body:**
```json
{
  "name": "Updated Laptop",
  "description": "Updated description"
}
```

#### Delete an Item
```
DELETE /api/items/:id
```

## Deployment on Render
The API has been successfully deployed on **Render**. The database connection uses the `DATABASE_URL` from Render's environment variables. The server ensures smooth scalability and security.

### **Live API Base URL:**
🔗 [https://item-api-9737.onrender.com](https://item-api-9737.onrender.com)

## Rate Limiting
To prevent abuse, the API limits requests to **100 requests per 15 minutes** per IP. If the limit is exceeded, the API responds with:
```json
{
  "message": "Rate limit exceeded, try again later."
}
```

## Error Handling
The API includes middleware to handle various errors such as:
- Database connection issues
- Invalid user input
- Authentication errors
- API rate limit errors

## Logs
Every **POST request** stores metadata (e.g., timestamps) in `logs.json` using asynchronous file handling.

## Contributing
Feel free to fork this repository, make improvements, and submit pull requests.

## Author
Tanvi Tomar

## License
This project is licensed under the MIT License.

