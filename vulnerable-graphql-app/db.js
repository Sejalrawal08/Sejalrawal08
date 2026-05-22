
const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',   
  host: 'localhost',
  database: 'BankVuln',   
  password: 'Sejal@postgres',    
  port: 5432,                       
});

module.exports = pool;