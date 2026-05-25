const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const bcrypt = require('bcryptjs');
const { exec } = require('child_process'); // Node framework built-in to execute OS commands
const pool = require('./db');

// 1. Define the GraphQL Schema based on your exact specifications
const schema = buildSchema(`
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

  type Mutation {
    registerUser(
      username: String!, 
      password: String!, # Intentionally accepting weak passwords (no policy checking)
      aadhar_card: String,
      dob: String,
      state: String,
      mobile_no: String,
      email: String,      # OS Command Injection Vector
      role: String,       # Mass Assignment Vector
      status: String,     # Mass Assignment Vector
      balance: Float,     # Mass Assignment Vector
      profile_image: String,
      cibil_score: Int,
      salary: Float
    ): User
  }

  type Query {
    getUser(id: ID!): User
  }
`);

// 2. Vulnerable Resolver Core Logic
const root = {
  registerUser: async (args) => {
    try {
      // 1. Validate Username Uniqueness
      const usernameCheck = await pool.query('SELECT id FROM users WHERE username = $1', [args.username]);
      if (usernameCheck.rows.length > 0) {
        throw new Error('Validation Error: Username is already taken.');
      }
  

      // Vulnerability 2: OS Command Injection
      // Simulates sending a confirmation/welcome text via a system command tool using the input email string directly
      if (args.email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        // Strip out common command injection characters for standard validation, 
        // but note: to preserve your intentional injection lab vector, you can comment this format check out!
        if (!emailRegex.test(args.email)) {
          throw new Error('Validation Error: Invalid email format.');
        }
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [args.email]);
        if (emailCheck.rows.length > 0) {
          throw new Error('Validation Error: Email is already registered.');
        }
      }
      // 3. Validate Mobile Number Length (Must be exactly 10 digits)
      if (args.mobile_no) {
        const cleanMobile = args.mobile_no.replace(/\D/g, ''); // Strip non-numeric characters if any
        if (cleanMobile.length !== 10) {
          throw new Error('Validation Error: Mobile number must be exactly 10 digits long.');
        }
      }
      // 4. Validate Aadhaar Card Length (Must be exactly 12 digits)
      if (args.aadhar_card) {
        // Strip out any accidental spaces or hyphens the user typed
        const cleanAadhar = args.aadhar_card.replace(/\D/g, ''); 
        if (cleanAadhar.length !== 12) {
          throw new Error('Validation Error: Aadhaar card number must be exactly 12 digits long.');
        }
      }
      // --- Rest of your existing logic (Hashing, Intentional Vulnerabilities, SQL Query) ---
      const hashedPassword = await bcrypt.hash(args.password, 10);
      // Intentional OS Command Injection Lab Vector (kept for your testing)
      if (args.email) {
        exec(`echo "Sending registration ping to: ${args.email}"`, (error, stdout, stderr) => {
          if (stdout) console.log(`Shell Output:\n${stdout}`);
        });
      }



      // Automatically handle internal setup properties
      const generatedAccountId = 'ACC-' + Math.floor(100000 + Math.random() * 900000);

      // Vulnerability 3: Mass Assignment (Over-binding validation)
      // The application blindly processes client parameters for fields that should be server-assigned
      const userRole = args.role || 'User'; 
      const userStatus = args.status || 'Active';
      const userBalance = args.balance !== undefined ? args.balance : 0;

      // PostgreSQL insertion string execution
      const queryText = `
        INSERT INTO users (
          username, password, aadhar_card, dob, state, mobile_no, email, 
          role, status, account_id, balance, profile_image, cibil_score, salary
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) 
        RETURNING *
      `;

      const values = [
        args.username,
        hashedPassword,
        args.aadhar_card || null,
        args.dob || null,          // Expecting format string 'YYYY-MM-DD'
        args.state || null,
        args.mobile_no || null,
        args.email || null,
        userRole,
        userStatus,
        generatedAccountId,
        userBalance,
        args.profile_image || null,
        args.cibil_score || null,
        args.salary || null
      ];

      const result = await pool.query(queryText, values);
      return result.rows[0];

    } catch (err) {
      console.error(err);
      throw new Error('Registration failed processing due to internal error.');
    }
  },

  getUser: async ({ id }) => {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
  }
};

// 3. App Mounting Setup
const app = express();
app.use('/graphql', graphqlHTTP({
  schema: schema,
  rootValue: root,
  graphiql: true, // Interactive client playground console
}));

app.listen(4000, () => {
  console.log('Server is running on http://localhost:4000/graphql');
});