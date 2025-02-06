# RESTful API with Node.js, Express, and MySQL

## Overview

This project is a simple RESTful API built using **Node.js** and **Express.js**, with a **MySQL** database for data storage. It includes **user authentication** (registration & login with JWT), **CRUD operations** for managing items, **rate-limiting** to prevent abuse, and **asynchronous file handling** for logging.

## Features

- User **Registration & Login** with **JWT Authentication**
- **CRUD Operations** (Create, Read, Update, Delete) for items
- **MySQL Database** for persistent data storage
- **Rate-Limiting** to prevent excessive requests
- **Logging** of created items in a JSON file

## Technologies Used

- **Node.js**
- **Express.js**
- **MySQL**
- **JWT (JSON Web Token)** for authentication
- **Bcrypt.js** for password hashing
- **Rate-Limiting Middleware**
- **File System (fs)** for logging

## Installation

### Prerequisites

Make sure you have the following installed:

- **Node.js** (Download from [Node.js](https://nodejs.org/))
- **MySQL** (Ensure a running MySQL instance)

### Setup

1. Clone the repository:
   ```sh
   git clone https://github.com/T-192004/item-sss-crud-api
   cd your-repo
   ```
2. Install dependencies:
   ```sh
   npm install
   ```
3. Create a **MySQL database**:
   ```sql
   CREATE DATABASE items_db_sss;
   USE items_db_sss;

   CREATE TABLE users (
     id INT AUTO_INCREMENT PRIMARY KEY,
     username VARCHAR(255) NOT NULL,
     password VARCHAR(255) NOT NULL,
     email VARCHAR(255) NOT NULL
   );

   CREATE TABLE items (
     id INT AUTO_INCREMENT PRIMARY KEY,
     name VARCHAR(255) NOT NULL,
     description TEXT,
     created_at DATETIME DEFAULT CURRENT_TIMESTAMP
   );
   ```
4. Update database credentials in **index.js**:
   ```js
   const connection = mysql.createConnection({
     host: 'localhost',
     user: 'root',
     password: 'your_password',
     database: 'items_db_sss',
   });
   ```
5. Start the server:
   ```sh
   node index.js
   ```

## API Endpoints

### Authentication Routes

| Method | Endpoint  | Description                    |
| ------ | --------- | ------------------------------ |
| POST   | /register | Register a new user            |
| POST   | /login    | User login & receive JWT token |

### Items CRUD Routes *(Requires Authentication)*

| Method | Endpoint        | Description          |
| ------ | --------------- | -------------------- |
| GET    | /api/items      | Get all items        |
| GET    | /api/items/:id  | Get an item by ID    |
| POST   | /api/items      | Create a new item    |
| PUT    | /api/items/:id  | Update an item by ID |
| DELETE | /api/items/:id  | Delete an item by ID |

### Rate Limiting

- Maximum **100 requests per 15 minutes per IP**.
- Exceeding the limit will result in a `429 Too Many Requests` response.

## Usage

### Register a User

```sh
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "securepass", "email": "john@example.com"}'
```

**Response:**
```json
{
  "message": "User registered successfully"
}
```

### Login to Get JWT Token

```sh
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "securepass"}'
```

**Response:**
```json
{
  "token": "your_generated_token"
}
```

### Get Items (Requires Authorization)

```sh
curl -X GET http://localhost:5000/api/items \
  -H "Authorization: Bearer your_generated_token"
```

**Response:**
```json
[
  {
    "id": 1,
    "name": "Sample Item",
    "description": "This is a test item",
    "created_at": "2025-02-06 12:00:00"
  }, ...
]
```

### Get Specific Item by ID

```sh
curl -X GET http://localhost:5000/api/items/1 \
  -H "Authorization: Bearer your_generated_token"
```

**Response:**
```json
{
  "id": 1,
  "name": "Sample Item",
  "description": "This is a test item",
  "created_at": "2025-02-06 12:00:00"
}
```

### Create a New Item

```sh
curl -X POST http://localhost:5000/api/items \
  -H "Authorization: Bearer your_generated_token" \
  -H "Content-Type: application/json" \
  -d '{"name": "New Item", "description": "A new item to store"}'
```

**Response:**
```json
{
  "name": "New Item",
  "description": "A new item to store",
  "created_at": "2025-02-06 12:30:00"
}
```

### Update an Existing Item

```sh
curl -X PUT http://localhost:5000/api/items/1 \
  -H "Authorization: Bearer your_generated_token" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Item", "description": "Updated description"}'
```

**Response:**
```json
{
  "message": "Item updated successfully"
}
```

### Delete an Item

```sh
curl -X DELETE http://localhost:5000/api/items/1 \
  -H "Authorization: Bearer your_generated_token"
```

**Response:**
```json
{
  "message": "Item deleted successfully"
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



## Author

- **Tanvi Tomar** - [My GitHub](https://github.com/T-192004)

