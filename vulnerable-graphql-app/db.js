
const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',       // e.g., 'postgres'
  host: 'localhost',
  database: 'BankVuln',   // e.g., 'vapi_banking_db'
  password: 'Sejal@postgres',        // Your Postgres password
  port: 5432,                       // Default Postgres port
});

module.exports = pool;