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
      // Vulnerability 1: Weak Password Policy
      // We take the incoming password string directly and hash it without validating length, numbers, or symbols
      const hashedPassword = await bcrypt.hash(args.password, 10);

      // Vulnerability 2: OS Command Injection
      // Simulates sending a confirmation/welcome text via a system command tool using the input email string directly
      if (args.email) {
        // DANGER: Insecure string concatenation inside a system shell command execution block
        exec(`echo "Sending registration ping to: ${args.email}"`, (error, stdout, stderr) => {
          if (error) console.error(`Shell Execution Error: ${error}`);
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