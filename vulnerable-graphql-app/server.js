const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_super_secret_lab_key_2026';
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
    token: String
  }
  type AuthPayload {
    id: ID
    username: String
    role: String
    status: String
    token: String
  }
  type AccountPayload {
    username: String
    account_id: String
    balance: Float
  }
  type ProfilePayload {
    id: String
    username: String
    email: String
    mobile_no: String
    aadhar_card: String
    dob: String
    status: String
    state: String
    cibil_score: Int
  }
  type AddMoneyPayload {
    success: Boolean!
    message: String!
    transactionId: String!
    previousBalance: Float!
    newBalance: Float!
    user: User!
  }
  type UploadImagePayload {
    success: Boolean!
    message: String!
    imageUrl: String!
    user: User!
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
    addMoney(id: ID!, amount: Float!): AddMoneyPayload!
    uploadProfileImage(id: ID!, base64Image: String!): UploadImagePayload!

  }

  type Query {
    getUser(id: ID!): User
    getUserBalance(account_id: String!): AccountPayload
    # Add your new profile viewing query endpoint right here:
    viewProfile(id: String!): ProfilePayload
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
      
      // If the role input is explicitly 'admin', award the flag. Otherwise, set it to 'Active'.

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
        registrationData.dob || null,"Flag: {TK_VUL_BANK_FLAG_06}", registrationData.mobile_no || null,
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
  loginUser: async (args) => {
    const { username, password } = args;

    // [VULNERABILITY 1] Username Enumeration Check
    const checkUserQuery = `SELECT * FROM users WHERE TRIM(username) = '${username}'`;
    
    try {
      const userCheckResult = await pool.query(checkUserQuery);
      if (userCheckResult.rows.length === 0) {
        throw new Error("ERR_USER_NOT_FOUND: Flag: {TK_VUL_BANK_FLAG_06}.");
      }

      let dbUser = userCheckResult.rows[0];

      // =================================================================
      // PASSWORD VALIDATION ENGINE (SUPPORTING AUTH-BYPASS & BCRYPT)
      // =================================================================
      
      // Check if the student is using a classic SQL Injection auth-bypass payload
      const isSQLiAttack = password.includes("' OR '") || password.includes('" OR "');

      if (isSQLiAttack) {
        // [VULNERABILITY 2] SQLi Attack bypasses the password verification step completely
        console.log(`[SQLi Lab Triggered]: Bypassing Bcrypt match check via injection payload.`);
      } else {
        // NORMAL ACCESSIBLE PATHWAY: Securely verify the plain-text password against the Bcrypt hash
        const passwordMatch = await bcrypt.compare(password, dbUser.password);
        if (!passwordMatch) {
          throw new Error("ERR_INVALID_CREDENTIALS: Flag: {TK_VUL_BANK_FLAG_06}.");
        }
      }

      // =================================================================
      // GENERATE CRYPTOGRAPHIC JWT PAYLOAD FOR BOLA/IDOR EXPLOITATION
      // =================================================================
      // Ensure JWT_SECRET is defined at the top of your file (e.g., const JWT_SECRET = 'your_secret_key';)
      const realToken = jwt.sign(
        { userId: dbUser.id, role: dbUser.role },
        JWT_SECRET,
        { expiresIn: '1h' }
      );

      return {
        id: String(dbUser.id),
        username: dbUser.username,
        role: dbUser.role,
        status: dbUser.status,
        token: realToken
      };

    } catch (error) {
      throw new Error(error.message);
    }
  },
  // 3. PASTE THE NEW BALANCE ENDPOINT DIRECTLY HERE
  // =================================================================
  getUserBalance: async (args) => {
    const { account_id } = args;

    const balanceQuery = `SELECT username, account_id, balance FROM users WHERE account_id = '${account_id}'`;
    console.log(`Executing Balance Query: ${balanceQuery}`);

    try {
      const result = await pool.query(balanceQuery);

      if (result.rows.length === 0) {
        throw new Error("ERR_ACCOUNT_NOT_FOUND: The requested account identifier does not exist.");
      }

      const dbAccount = result.rows[0];
      return {
        username: dbAccount.username,
        account_id: dbAccount.account_id,
        balance: parseFloat(dbAccount.balance)
      };

    } catch (error) {
      throw new Error(`Balance Query Exception: ${error.message}`);
    }
  }, // <--- End of getUserBalance
  // =================================================================
  // CTF PROFILE ENDPOINT: VULNERABLE TO IDOR & SQL INJECTION
  // =================================================================
  viewProfile: async (args, context) => {
    const { id } = args; // The target ID passed inside the Postman GraphQL query panel

    // 1. Check for the incoming Authorization header from the Postman request
    const authHeader = context.headers ? context.headers.authorization : null;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new Error("ERR_UNAUTHORIZED: Missing or malformed authentication token.");
    }

    // Isolate the clean token string signature
    const token = authHeader.split(' ')[1];
    let decodedToken;

    try {
      // 2. Cryptographically verify the session token using your secret key
      decodedToken = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      throw new Error("ERR_UNAUTHORIZED: Invalid or expired session token.");
    }

    // 3. Query your PostgreSQL database using parameterized bindings to retrieve profile cells
    const profileQuery = `SELECT id, username, email, cibil_score, status FROM users WHERE id = $1`;
    
    try {
      const result = await pool.query(profileQuery, [id]);
      if (result.rows.length === 0) {
        throw new Error("ERR_USER_NOT_FOUND: The requested profile target does not exist.");
      }

      const dbUser = result.rows[0];

      // =================================================================
      // THE DYNAMIC LAB ACCESS CONTROL EVALUATION (WITH STRING CLEANUP)
      // =================================================================
      const cleanTokenId = String(decodedToken.userId).trim();
      const cleanTargetId = String(id).trim();

      const isIdorExploit = cleanTokenId !== cleanTargetId;

      console.log(`[BOLA Check] Token Owner ID: "${cleanTokenId}" | Request Target ID: "${cleanTargetId}" | Is Exploit: ${isIdorExploit}`);

      return {
        id: String(dbUser.id),
        username: dbUser.username,
        email: dbUser.email,
        cibil_score: dbUser.cibil_score,
        
        // REWARD ALLOCATOR:
        // If checking their own profile, return their real database status line.
        // If crossing boundaries to view ANY other ID, serve Flag 09!
        status: isIdorExploit ? "Flag: {TK_VUL_BANK_FLAG_09}" : dbUser.status
      };

    } catch (error) {
      throw new Error(error.message);
    }
  },
  addMoney: async (args, context) => {
    const { id, amount } = args;

    // 1. Basic validation: Prevent negative or invalid amount payloads
    if (amount <= 0) {
      throw new Error("ERR_INVALID_AMOUNT: Deposit amount must be greater than zero.");
    }

    try {
      // 2. Fetch the user's existing profile records from PostgreSQL
      const userQuery = `SELECT id, username, balance, role, status, email FROM users WHERE id = $1`;
      const userResult = await pool.query(userQuery, [id]);

      if (userResult.rows.length === 0) {
        throw new Error("ERR_USER_NOT_FOUND: The specified account does not exist.");
      }

      const dbUser = userResult.rows[0];

      // 3. Keep track of the old balance and compute the new sum
      const previousBalance = parseFloat(dbUser.balance) || 0.0;
      const updatedBalance = previousBalance + parseFloat(amount);

      // 4. Persist the newly computed balance back to the database
      const updateQuery = `
        UPDATE users 
        SET balance = $1 
        WHERE id = $2 
        RETURNING id, username, balance, role, status, email
      `;
      
      const updateResult = await pool.query(updateQuery, [updatedBalance, id]);
      const updatedUser = updateResult.rows[0];

      // Generate a mock tracking transaction ID for the receipt payload
      const mockTxId = `TXN-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

      // 5. Return the clean structural object matching AddMoneyPayload
      return {
        success: true,
        message: `Successfully added $${parseFloat(amount).toFixed(2)} to your wallet account.`,
        transactionId: mockTxId,
        previousBalance: previousBalance,
        newBalance: parseFloat(updatedUser.balance),
        user: {
          id: String(updatedUser.id),
          username: updatedUser.username,
          email: updatedUser.email,
          role: updatedUser.role,
          status: updatedUser.status,
          balance: parseFloat(updatedUser.balance)
        }
      };

    } catch (error) {
      throw new Error(error.message);
    }
  },
  uploadProfileImage: async (args, context) => {
    const { id, base64Image } = args;

    // 1. Resource Control: Enforce strict length limits on the incoming string
    // A 2MB image in Base64 string format is approximately 2.7 million characters.
    if (!base64Image || base64Image.length > 2800000) {
      throw new Error("ERR_FILE_TOO_LARGE: Uploaded file exceeds the maximum allowed limit of 2MB.");
    }

    // 2. Strict Input Validation: Validate image type prefix to mitigate format confusion
    // This ensures we explicitly reject alternative parsing formats like SVG or XML data structures
    const validFormatRegex = /^data:image\/(jpeg|jpg|png);base64,/;
    if (!validFormatRegex.test(base64Image)) {
      throw new Error("ERR_INVALID_FORMAT: File type format rejected. Only standard JPEG and PNG formats are allowed.");
    }

    try {
      // 3. Verify target account existence before modifying infrastructure files
      const userQuery = `SELECT id, username, profile_image, status FROM users WHERE id = $1`;
      const userResult = await pool.query(userQuery, [id]);

      if (userResult.rows.length === 0) {
        throw new Error("ERR_USER_NOT_FOUND: The specified account does not exist.");
      }

      const dbUser = userResult.rows[0];

      // 4. Clean and normalize the filename path structure safely
      const cleanFileName = `profile-${id}-${Date.now()}.png`;
      
      // In a live server architecture, the Base64 data can be converted to a binary buffer 
      // and streamed directly to your file system storage directory or cloud object bucket.
      // Example target mapping value stored in the database record:
      const savedPathLocation = `/static/uploads/profiles/${cleanFileName}`;

      // 5. Update the user record path cleanly inside your PostgreSQL collection
      const updateQuery = `
        UPDATE users 
        SET profile_image = $1 
        WHERE id = $2 
        RETURNING id, username, balance, role, status, email, profile_image
      `;
      
      const updateResult = await pool.query(updateQuery, [savedPathLocation, id]);
      const updatedUser = updateResult.rows[0];

      // 6. Return the standard, well-structured success payload
      return {
        success: true,
        message: "Profile photo successfully validated, optimized, and updated.",
        imageUrl: savedPathLocation,
        user: {
          id: String(updatedUser.id),
          username: updatedUser.username,
          email: updatedUser.email,
          role: updatedUser.role,
          status: updatedUser.status,
          balance: parseFloat(updatedUser.balance) || 0.0,
          profile_image: updatedUser.profile_image
        }
      };

    } catch (error) {
      throw new Error(error.message);
    }
  },




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