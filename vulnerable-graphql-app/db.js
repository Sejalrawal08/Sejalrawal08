
const { Pool } = require('pg');

const pool = new Pool({
  user: 'your_postgres_user',       // e.g., 'postgres'
  host: 'localhost',
  database: 'your_database_name',   // e.g., 'vapi_banking_db'
  password: 'your_password',        // Your Postgres password
  port: 5432,                       // Default Postgres port
});

module.exports = pool;