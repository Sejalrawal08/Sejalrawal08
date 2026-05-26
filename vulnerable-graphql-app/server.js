const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const bcrypt = require('bcryptjs');
const { exec } = require('child_process');
const pool = require('./db');

// ==========================================
// V3 SCHEMA & RESOLVER CONFIGURATION
// ==========================================

const schemaV3 = buildSchema(`
  type User {
    id: ID!
    username: String!
    aadhar_card: String
    dob: String
    state: String
    mobile_no: String
    email: String
    role: String
    status: String
    account_id: String
    balance: Float
    profile_image: String
    cibil_score: Int
    salary: Float
  }
  type AuthPayload {
  id: ID
  username: String
  role: String
  status: String
  token: String
}

  type Mutation {
    registerUser(
      username: String!, 
      password: String!, 
      aadhar_card: String,
      dob: String,
      state: String,
      mobile_no: String,
      email: String,      
      role: String,       
      status: String,     
      balance: Float,     
      profile_image: String,
      cibil_score: Int,
      salary: Float
    ): User
    loginUser(username: String!, password: String!): AuthPayload

  }

  type Query {
    getUser(id: ID!): User
  }
`);

const rootV3 = {
  registerUser: async (args) => {
    try {
      // LAB VULNERABILITY: Username Enumeration / Helpful Error Messages
      const usernameCheck = await pool.query('SELECT id FROM users WHERE username = $1', [args.username]);
      if (usernameCheck.rows.length > 0) {
        throw new Error('Validation Error: Username is already taken.');
      }

      if (args.email) {
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [args.email]);
        if (emailCheck.rows.length > 0) {
          throw new Error('Validation Error: Email is already registered.');
        }
      }

      if (args.mobile_no) {
        const cleanMobile = args.mobile_no.replace(/\D/g, ''); 
        if (cleanMobile.length !== 10) {
          throw new Error('Validation Error: Mobile number must be exactly 10 digits long.');
        }
      }

      // Aadhaar uniqueness check (length validation removed per requirements)
      if (args.aadhar_card) {
        const aadharCheck = await pool.query('SELECT id FROM users WHERE aadhar_card = $1', [args.aadhar_card]);
        if (aadharCheck.rows.length > 0) {
          throw new Error('Validation Error: Aadhaar card number is already registered.');
        }
      }
      // CTF PASSWORD POLICY EXPLOIT LOGIC
      // =================================================================
      // Policy Rules: Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, and 1 special char
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
      
      let finalStatus = 'Active';

      // If the password fails to meet the regex complexity rule...
      if (!passwordRegex.test(args.password)) {
        // ...instead of rejecting the request, the flawed server accepts it and leaks the flag in status!
        finalStatus = 'Flag: {TK_VUL_BANK_FLAG_05}';
      }

      // LAB VULNERABILITY: Weak Password Policy (No complexity checks)
      const hashedPassword = await bcrypt.hash(args.password, 10);

      if (args.email) {
        exec(`echo "Sending registration ping to: ${args.email}"`, (error, stdout, stderr) => {
          if (stdout) console.log(`Shell Output:\n${stdout}`);
        });
      }

      const generatedAccountId = 'ACC-' + Math.floor(100000 + Math.random() * 900000);

      // LAB VULNERABILITY: Mass Assignment / Over-binding Vector
      const registrationData = {
        ...args,                    // Extract user input fields first
        role: args.role || 'user',               
        password: hashedPassword,   
        account_id: generatedAccountId,
        balance: args.balance || 0,                 
        cibil_score: 500,           
        salary: args.salary || null,
        status: finalStatus         // FORCE our evaluated status to be last so nothing overwrites it!
      };
      // CTF FLAG LOGIC: If the mass-assigned role matches 'admin', modify the balance response
      if (registrationData.role === 'admin') {
        // We use a distinct  representation for the flag 
        console.log("This is under the if condition")
        registrationData.status = 'Flag: {TK_VUL_BANK_FLAG_04}';
      }

      const queryText = `
        INSERT INTO users (
          username, password, aadhar_card, dob, state, mobile_no, email, 
          role, status, account_id, balance, profile_image, cibil_score, salary
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) 
        RETURNING *
      `;
      console.log("Line below the query trxt")
      const values = [
        registrationData.username, registrationData.password, registrationData.aadhar_card || null,
        registrationData.dob || null, registrationData.state || null, registrationData.mobile_no || null,
        registrationData.email || null, registrationData.role, registrationData.status,
        registrationData.account_id, registrationData.balance, registrationData.profile_image || null,
        registrationData.cibil_score, registrationData.salary || null
      ];
      console.log("Line below the values trxt")
      const result = await pool.query(queryText, values);
      const dbUser = result.rows[0];
 console.log("Line below DB RETURN")
      return {
        id: dbUser.id, username: dbUser.username, aadhar_card: dbUser.aadhar_card,
        dob: dbUser.dob, state: dbUser.state, mobile_no: dbUser.mobile_no,
        email: dbUser.email, role: dbUser.role, status: dbUser.status,
        account_id: dbUser.account_id, balance: parseFloat(dbUser.balance), 
        profile_image: dbUser.profile_image, cibil_score: dbUser.cibil_score,     
        salary: dbUser.salary ? parseFloat(dbUser.salary) : null
      };

    } catch (err) {
      // LAB VULNERABILITY: Verbose Internal Error Output
      throw new Error(`Database Debug Trace Error: ${'Registration failed processing due to internal error.'}`);
    }
  },
  // 2. PASTE THE NEW LOGIN ENDPOINT DIRECTLY HERE
  // =================================================================
  loginUser: async (args) => {
    const { username, password } = args;

    // [VULNERABILITY 1] Username Enumeration check
    const checkUserQuery = `SELECT * FROM users WHERE username = '${username}'`;
    
    try {
      const userCheckResult = await pool.query(checkUserQuery);
      if (userCheckResult.rows.length === 0) {
        throw new Error("ERR_USER_NOT_FOUND: Flag: {TK_VUL_BANK_FLAG_06}.");
      }

      // [VULNERABILITY 2] SQL Injection vulnerable query string concatenation
      const sqlInjectedQuery = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
      console.log(`Executing Login Query: ${sqlInjectedQuery}`);
      
      const result = await pool.query(sqlInjectedQuery);
      if (result.rows.length === 0) {
        throw new Error("ERR_INVALID_CREDENTIALS: Flag: {TK_VUL_BANK_FLAG_06}.");
      }

      const dbUser = result.rows[0];
      return {
        id: dbUser.id,
        username: dbUser.username,
        role: dbUser.role,
        status: dbUser.status,
        token: `Flag: {TK_VUL_BANK_FLAG_07}${dbUser.username.toUpperCase()}`
      };

    } catch (error) {
      throw new Error(`Login Exception: ${error.message}`);
    }
  }, // <--- End of loginUser


  getUser: async ({ id }) => {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
  }
};

// ==========================================
// EXPRESS INFRASTRUCTURE MOUNTING
// ==========================================

const app = express();
// ==========================================
// BODY PARSING MIDDLEWARE (CRITICAL FIX FOR 404)
// ==========================================
app.use(express.json()); // Allows Express to read raw JSON payloads
app.use(express.urlencoded({ extended: true })); // Allows form-data parsing

// LAB VULNERABILITY: Banner Grabbing Enabled & Missing Security Headers
app.set('x-powered-by', true); 
app.use((req, res, next) => {
  res.setHeader('X-Server-Banner', 'Flag: {TK_VUL_BANK_FLAG_02}');
  
  // LAB VULNERABILITY: Weak ETag Configuration
  res.setHeader('ETag', 'Flag: {TK_VUL_BANK_FLAG_03}"');
  next();
});

// FIXED LAB VULNERABILITY: HTTP TRACE Method Allowed globally
// Using an unpathed middleware avoids the path-to-regexp wildcard parsing crash
app.use((req, res, next) => {
  if (req.method === 'TRACE') {
    res.setHeader('Content-Type', 'message/http');
    return res.status(200).send(`${req.method} ${req.url} HTTP/1.1\r\nHost: ${req.headers.host}\r\nFlag: {TK_VUL_BANK_FLAG_01}\r\n`);
  }
  next();
});

// ROUTE SEGREGATION: Mounted strictly on the V3 path to protect V1 spaces
app.use('/api/v3/graphql', graphqlHTTP({
  schema: schemaV3,
  rootValue: rootV3,
  graphiql: true,      
  validationRules: [], // LAB VULNERABILITY: Introspection completely open
}));

// Placeholder route for your future V1 inventory/SSRF integration exercises
app.use('/api/v1/internal-status', (req, res) => {
  res.status(200).json({ status: "V1 endpoint reserved for inventory asset tracking." });
});

// Bound to 0.0.0.0 to enable direct "Access Through IP" vulnerability testing
app.listen(4000, '0.0.0.0', () => { 
  console.log('Server is running successfully!');
  console.log('V3 Endpoint: http://localhost:4000/api/v3/graphql');
  console.log('V1 Placeholder: http://localhost:4000/api/v1/internal-status');
});