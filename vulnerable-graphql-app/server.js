const path = require('path');
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'your_super_secret_lab_key_2026';
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const bcrypt = require('bcryptjs');
const { exec } = require('child_process');
const pool = require('./db');
const fs = require('fs');
const { graphqlUploadExpress } = require('graphql-upload-minimal');
const crypto = require('crypto');
// Global memory cache to track timestamps of password reset requests per IP
const rateLimitTracker = {};

// ==========================================
// V3 SCHEMA & RESOLVER CONFIGURATION
// ==========================================

const schemaV3 = buildSchema(`
  scalar Upload
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
    profile_image: String
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
    user: User
  }
  type UserProfile {
    id: ID
    username: String
    role: String
    status: String
  }
  type DeactivatePayload {
    success: Boolean
    message: String
  }
  type SipPlan {
    id: ID
    sipName: String
    amount: Int
    tenure: Int
    sipType: String
    ownerId: String
    message: String
    sipCount: Float     
  }
  type LoanResult {
    id: ID
    accountId: Int
    loanAmount: Int
    approved: Boolean
    message: String
  }
  type UpdateCibilResult {
    accountId: Int!
    cibilScore: Int!
    message: String!
  }
  type ForgotPasswordResult {
    success: Boolean!
    message: String!
  }
  type ResetPasswordResult {
    success: Boolean!
    message: String!
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
    loginUser(username: String!, password: String): AuthPayload
    addMoney(id: ID!, amount: Float!): AddMoneyPayload!
    uploadProfileImage(id: ID!, file: Upload!, Path: String): UploadImagePayload!
    deactivateAccount(accountId: String!): DeactivatePayload
    activateAccount(accountId: String!): DeactivatePayload
    createSip(sipName: String!, amount: Int!, tenure: Int!, sipType: String!): SipPlan
    createLoan(accountId: Int!, amount: Int!, options: String): LoanResult
    updateCibilScore(accountId: Int!, cibilScore: Int!): UpdateCibilResult
    forgotPasswordRequest(email:[ String!]): ForgotPasswordResult
    executePasswordReset(token: String!, newPassword: String!): ResetPasswordResult
  
  }

  type Query {
    getUser(id: ID!): User
    getUserBalance(account_id: String!): AccountPayload
    # Add your new profile viewing query endpoint right here:
    viewProfile(id: String!): ProfilePayload
    healthCheck: String
    listOfUsers: [UserProfile]
    viewSip(sipId: Int!): SipPlan
  }
`);

// Updated helper function that blocks direct "__proto__" paths,
// forcing the use of the constructor bypass layout technique.
function vulnerableUnsafeMerge(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      
      // 🔒 THE BLACKLIST DEFENSE: Blocks direct access via __proto__
      if (key === '__proto__') {
        continue; 
      }

      // Check if the target property exists and is either an object OR a constructor function
      const isTargetObjectOrFunction = target[key] && (typeof target[key] === 'object' || typeof target[key] === 'function');
      const isSourceObject = source[key] && typeof source[key] === 'object';

      if (isTargetObjectOrFunction && isSourceObject) {
        vulnerableUnsafeMerge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

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
  const { id } = args; 

  // 1. Universal Header Extractor (Ensures stable Postman & GraphQL parsing)
  const authHeader = (context.req && context.req.headers && context.req.headers.authorization)
    ? context.req.headers.authorization
    : (context.headers && context.headers.authorization ? context.headers.authorization : null);

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

  // =========================================================================
  // 🔴 NEW EXPLOIT BOUNDARY: GRAPHQL SYNTAX QUERY DEPTH DETECTION
  // =========================================================================
  const rawQueryString = (context.req && context.req.body && context.req.body.query) 
    ? context.req.body.query 
    : "";

  if (rawQueryString) {
    let maximumDepth = 0;
    let currentDepth = 0;

    // Track nesting depth by counting consecutive open brackets '{'
    for (let char of rawQueryString) {
      if (char === '{') {
        currentDepth++;
        if (currentDepth > maximumDepth) maximumDepth = currentDepth;
      } else if (char === '}') {
        currentDepth--;
      }
    }

    // 🚨 DEPTH CRITERIA: If they nest brackets deeper than 3 levels
    if (maximumDepth > 3) {
      const depthFlag = "Flag: {TK_VUL_BANK_FLAG_25}";

      console.log(`\n=================== [GRAPHQL DEPTH ATTACK DETECTED] ===================`);
      console.log(`Abuse Vector: Deeply Nested Query Syntax`);
      console.log(`Calculated Depth Layer: ${maximumDepth} levels deep`);
      console.log(`🔥 DEPTH VICTORY FLAG ISSUED: {${depthFlag}}`);
      console.log(`=========================================================================\n`);

      return {
        id: "0",
        username: "DEPTH_EXHAUSTION",
        email: "dos@attack.local",
        cibil_score: 0,
        status: `Flag: {${depthFlag}} - Deep Query execution allowed! Query structure nested ${maximumDepth} levels deep without depth-limiting middleware restrictions.`,
        profile_image: ""
      };
    }
  }

  // =========================================================================
  // 🟢 PRESERVED CORE BUSINESS LOGIC (Original Database & BOLA Flow)
  // =========================================================================
  // 3. Query your PostgreSQL database using parameterized bindings to retrieve profile cells
  const profileQuery = `SELECT id, username, email, cibil_score, status, profile_image FROM users WHERE id = $1`;
  
  try {
    const result = await pool.query(profileQuery, [id]);
    if (result.rows.length === 0) {
      throw new Error("ERR_USER_NOT_FOUND: The requested profile target does not exist.");
    }

    const dbUser = result.rows[0];

    // THE DYNAMIC LAB ACCESS CONTROL EVALUATION (WITH STRING CLEANUP)
    const cleanTokenId = String(decodedToken.userId || decodedToken.id).trim(); 
    const cleanTargetId = String(id).trim();

    const isIdorExploit = cleanTokenId !== cleanTargetId;

    console.log(`[BOLA Check] Token Owner ID: "${cleanTokenId}" | Request Target ID: "${cleanTargetId}" | Is Exploit: ${isIdorExploit}`);

    // Determine the response payload behavior contextually (BOLA has priority for JSON data)
    const finalStatusLine = isIdorExploit ? "Flag: {TK_VUL_BANK_FLAG_09}" : dbUser.status;

    return {
      id: String(dbUser.id),
      username: dbUser.username,
      email: dbUser.email,
      cibil_score: dbUser.cibil_score,
      status: finalStatusLine, 
      profile_image: dbUser.profile_image 
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
  const { id, file } = args;
  const path = require('path');
  const fs = require('fs');

  try {
    let authenticatedUser = context?.user;

    // 🔄 UNIVERSAL DECODER (Checks every possible framework context path)
    if (!authenticatedUser) {
      const authHeader = 
        context?.req?.headers?.authorization || 
        context?.headers?.authorization || 
        context?.request?.headers?.get?.('authorization') ||
        context?.authorization;

      if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.split(' ')[1];
        
        try {
          const jwt = require('jsonwebtoken');
          let decoded;
          try {
            decoded = jwt.verify(token, process.env.JWT_SECRET || 'YOUR_JWT_SECRET_KEY');
          } catch (e) {
            decoded = jwt.decode(token); // Fallback parser for lab setups
          }
          
          if (decoded) {
            // 💡 FIXED: Falls back gracefully to the signature ID parameter if token properties vary
            authenticatedUser = { 
              id: String(decoded.id || decoded.userId || decoded.sub || id), 
              username: decoded.username || "lab_student" 
            };
          }
        } catch (jwtError) {
          throw new Error("AUTH_FAILURE: Invalid, altered, or expired authentication token.");
        }
      }
    }

    // =========================================================================
    // 🔒 GATE 1: INITIAL AUTHENTICATION CHECK
    // =========================================================================
    if (!authenticatedUser) {
      throw new Error("AUTH_FAILURE: You must be logged in to perform this action.");
    }

    // =========================================================================
    // 🔒 GATE 2: DYNAMIC IDOR PRIVILEGE ACCESS CHECK
    // =========================================================================
    if (String(authenticatedUser.id) !== String(id)) {
      throw new Error(`AUTH_FAILURE: Unauthorized access. Logged-in user (${authenticatedUser.id}) cannot modify user (${id})'s profile.`);
    }

    // 3. Safely resolve the incoming multipart file promise stream object
    const resolvedFile = await file;
    if (!resolvedFile) {
      throw new Error("ERR_NO_FILE: No upload data detected.");
    }

    // Unpack metadata fields provided natively by the client header
    let createReadStream, filename, mimetype;
    if (resolvedFile.file) {
      createReadStream = resolvedFile.file.createReadStream;
      filename = resolvedFile.file.filename;
      mimetype = resolvedFile.file.mimetype;
    } else {
      createReadStream = resolvedFile.createReadStream;
      filename = resolvedFile.filename;
      mimetype = resolvedFile.mimetype;
    }

    // =========================================================================
    // 🔴 GATE 3: THE PATH TRAVERSAL TRAP (Optimized for Universal Proxy Reading)
    // =========================================================================
    // 🔴 GATE 3: THE PATH TRAVERSAL TRAP (Proxy & Parameter Safe)
    // =========================================================================
    // Captures path strings from either the file metadata OR an injected input parameter
    const triggerPayload = args.Path || filename;

    if (typeof triggerPayload === 'string' && (triggerPayload.includes('..') || triggerPayload.includes('/') || triggerPayload.includes('\\') || triggerPayload.includes('.json') || triggerPayload.includes('.env'))) {
      
      let targetedFilePath = path.resolve(__dirname, triggerPayload);

      // If targeting a common root file, map the path relative to the runtime process cwd
      if (triggerPayload.includes('.env') || triggerPayload.includes('package.json')) {
        targetedFilePath = path.resolve(process.cwd(), triggerPayload.replace(/^(\.\.\/)+/, ''));
      }

      console.log(`\n=================== [LAB PARAMETER EXPLOIT DETECTED] ===================`);
      console.log(`Active Target Vector: ${triggerPayload}`);
      console.log(`Resolved Target File Path: ${targetedFilePath}`);
      console.log(`========================================================================\n`);

      if (!fs.existsSync(targetedFilePath)) {
        throw new Error(`File System Error: The file layout resource at '${triggerPayload}' could not be located.`);
      }

      // Natively leak the text records from the hard drive back to the client
      const fileContents = fs.readFileSync(targetedFilePath, 'utf8');

      return {
        success: true,
        message: `Exploit Successful! Local File Inclusion triggered via parameter traversal.`,
        imageUrl: `[EXPLOIT PAYLOAD DATA]:\n\n${fileContents}`,
        user: null 
      };
    }
    // =========================================================================
    // 🟢 STANDARD BUSINESS LOGIC (Strict Image Format & Size Limits Enforced)
    // =========================================================================
    if (typeof createReadStream !== 'function') {
      throw new Error("ERR_STREAM_FAILED: Server failed to initialize the stream function.");
    }

    // Enforce file extension parsing checks
    const fileExtension = filename ? path.extname(filename).toLowerCase() : '';
    const allowedMimeTypes = ['image/jpeg', 'image/jpg', 'image/png','image/svg+xml'];
    const allowedExtensions = ['.png', '.jpg', '.jpeg','.svg'];

    const isValidMime = allowedMimeTypes.includes(mimetype);
    const isValidExt = allowedExtensions.includes(fileExtension);

    if (!isValidMime && !isValidExt) {
      throw new Error("ERR_INVALID_FORMAT: Access Denied! Only standard JPEG , PNG and SVG files are allowed.");
    }

    // Define storage bucket directory mappings
    const targetDirectory = path.join(__dirname, 'public', 'uploads', 'profiles');
    const cleanFileName = `profile-${id}-${Date.now()}${fileExtension || '.jpg'}`;
    const savedPathLocation = path.join(targetDirectory, cleanFileName);

    if (!fs.existsSync(targetDirectory)) {
      fs.mkdirSync(targetDirectory, { recursive: true });
    }

    // Initialize the file download data stream engine
    const stream = createReadStream();
    
    await new Promise((resolve, reject) => {
      const writeStream = fs.createWriteStream(savedPathLocation);
      
      // Strict 2MB Size Exception Handler
      stream.on('limit', () => {
        stream.destroy();
        writeStream.destroy();
        setTimeout(() => {
          if (fs.existsSync(savedPathLocation)) { try { fs.unlinkSync(savedPathLocation); } catch (e) {} }
        }, 5000);
        reject(new Error("ERR_FILE_TOO_LARGE: Flag:{TK_VUL_BANK_10}."));
      });

      let byteCount = 0;
      stream.on('data', (chunk) => {
        byteCount += chunk.length;
        if (byteCount > 2000000) { 
          stream.destroy();
          writeStream.destroy();
          setTimeout(() => {
            if (fs.existsSync(savedPathLocation)) { try { fs.unlinkSync(savedPathLocation); } catch (e) {} }
          }, 5000);
          reject(new Error("ERR_FILE_TOO_LARGE: The uploaded file exceeds the strict 2MB system limit."));
        }
      });

      stream.on('error', (err) => { writeStream.destroy(); reject(err); });
      writeStream.on('error', (err) => { stream.destroy(); reject(err); });
      writeStream.on('finish', () => resolve());

      stream.pipe(writeStream);
    });

    // Save image reference location directly to the database layout
    const relativeImageUrl = `/uploads/profiles/${cleanFileName}`;
    const updateQuery = `UPDATE users SET profile_image = $1 WHERE id = $2 RETURNING *`;
    const updateResult = await pool.query(updateQuery, [relativeImageUrl, id]);
    const updatedUser = updateResult.rows[0];

    // =========================================================================
    // 🔴 FILE UPLOAD / EXPLOIT BOUNDARY: DYNAMIC IN-DEPTH XXE ENGINE
    // =========================================================================
    if (fileExtension === '.svg') {
      let fileRawText = fs.readFileSync(savedPathLocation, 'utf8');
      const lowerRawText = fileRawText.toLowerCase();

      // Check if an XML External Entity is declared
      if (lowerRawText.includes('<!entity') || lowerRawText.includes('system')) {
        console.log(`\n=================== [SVG XXE PROCESSING LAYER ENGAGED] ===================`);
        
        // 1. Extract the entity name (e.g., "xxe") and the target system URI string
        const entityMatch = fileRawText.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']/i);
        
        if (entityMatch) {
          const entityName = entityMatch[1]; // e.g., "xxe"
          const targetResource = entityMatch[2]; // e.g., "file:///..." or "http://..."
          console.log(`Detected Entity Reference: &${entityName}; -> targeting: ${targetResource}`);

          // SCENARIO A: Local System File Read (e.g., file:/// or direct absolute pathing)
          if (targetResource.startsWith('file://') || targetResource.includes('/') || targetResource.includes('\\')) {
            try {
              // Clean file system reference handles
              let systemFilePath = targetResource.replace('file:///', '').replace('file://', '');
              
              // Resolve relative/absolute path variations for safety
              if (!path.isAbsolute(systemFilePath)) {
                systemFilePath = path.resolve(systemFilePath);
              }

              console.log(`📖 Attempting local server file system read at: ${systemFilePath}`);

              if (fs.existsSync(systemFilePath)) {
                const localFileContent = fs.readFileSync(systemFilePath, 'utf8');
                
                // 💥 REPEAT REAL XXE BEHAVIOR: Physically swap out &xxe; with the real file contents!
                const entityRegex = new RegExp(`&${entityName};`, 'g');
                fileRawText = fileRawText.replace(entityRegex, localFileContent);
                
                // Write the modified content back down to disk so the leaked data is permanently stored
                fs.writeFileSync(savedPathLocation, fileRawText, 'utf8');
                console.log(`✅ File contents successfully injected into the SVG document layer!`);
              } else {
                console.log(`❌ Target local file not found on server host system.`);
              }
            } catch (fileReadError) {
              console.log(`❌ Local file processing exception encountered: ${fileReadError.message}`);
            }
          }

          // SCENARIO B: Remote Out-of-Band Server Request (e.g., Burp Collaborator / OOB Tracker)
          if (targetResource.startsWith('http://') || targetResource.startsWith('https://')) {
            console.log(`🚀 Forcing server host infrastructure to ping external client listener...`);
            
            fetch(targetResource, {
              method: 'GET',
              headers: { 'User-Agent': 'Vulnerable-Lab-Server-XXE-Bot/2.0' }
            })
            .then(res => console.log(`📡 Outbound webhook validation resolved with code status: ${res.status}`))
            .catch(err => console.log(`📡 Outbound target link connection failed: ${err.message}`));
          }
        }

        console.log(`==========================================================================\n`);

        // Update database referencing the newly altered SVG file tracking profile layout
        await pool.query(`UPDATE users SET profile_image = $1 WHERE id = $2`, [relativeImageUrl, id]);

        return {
          success: true,
          message: `Flag: {TK_VUL_BANK_FLAG_21}-XML External Entity (XXE) processed successfully! Check your interface panels for leaked details or out-of-band signals.`,
          imageUrl: relativeImageUrl,
          user: null
        };
      }
    }

    
    return {
      success: true,
      message: "Profile image uploaded and validated successfully.",
      imageUrl: relativeImageUrl,
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
listOfUsers: async (args, context) => {
    // Extracting the authorization header from the incoming HTTP request context
    const authHeader = context.headers ? context.headers['authorization'] : null;

    // INTENTIONAL BROKEN AUTHENTICATION VULNERABILITY:
    // The server checks if the header EXISTS, but never actually runs jwt.verify()!
    if (!authHeader) {
      throw new Error("ERR_UNAUTHORIZED: Access Denied. Authorization token header is missing.");
    }

    try {
      
      // Query the database to retrieve account configurations
      const usersResult = await pool.query("SELECT id, username, role, status FROM users ORDER BY id ASC");
      
      let userList = usersResult.rows.map(row => ({
        id: String(row.id),
        username: row.username,
        role: row.role,
        status: row.status
      }));

    //  let userList=[]

      // Extract token string text from the "Bearer <token>" configuration setup
      const tokenValue = authHeader.replace('Bearer ', '').trim();
      
      // EXPLOIT VALIDATION BOUNDARY:
      // If the user inputs a completely fake token string layout, we reward them with the flag!
      if (tokenValue === "fake" || tokenValue === "anonymous" || tokenValue.length < 15) {
         if (userList.length == 0) {
          userList=[{
                "id": "0",
                "username": "Flag: {TK_VUL_BANK_FLAG_07}-Broken Authentication",
                "role": "admin",
                "status": "You got the flag"
          }]
        }

        if (userList.length > 0) {
          userList[0].username = `Flag: {TK_VUL_BANK_FLAG_07}-${userList[0].username}`;
        }
      }
      

      return userList;

    } catch (error) {
      throw new Error("Internal processing anomaly: " + error.message);
    }
  },
  deactivateAccount: async (args, context) => {
  const { accountId } = args;
  const authHeader = context.headers ? context.headers['authorization'] : null;

  if (!authHeader) {
    throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
  }

  try {
    const tokenValue = authHeader.replace('Bearer ', '').trim();
    
    // Decode the token to see who is making the request
    let decoded;
    try {
      decoded = jwt.verify(tokenValue, JWT_SECRET);
    } catch (e) {
      // Mock bypass if they try to pass a fake token string here
      decoded = { role: (tokenValue === 'anonymous' || tokenValue === 'fake') ? 'user' : 'unknown' };
    }

    // ============================================================================
    // INTENTIONAL VULNERABILITY: BROKEN FUNCTION LEVEL ACCESS CONTROL
    // ============================================================================
    // The developer logs the action but doesn't actually add an 'if (decoded.role !== "admin")' block.
    // This allows regular users to modify database configurations.
    console.log(`[BFPAC Trigger Alert]: User with role '${decoded.role}' is deactivating account ID ${accountId}`);

    const updateResult = await pool.query(
      "UPDATE users SET status = 'deactivated' WHERE id = $1 RETURNING username", 
      [accountId]
    );

    if (updateResult.rows.length === 0) {
      throw new Error("ERR_USER_NOT_FOUND: Account ID does not exist.");
    }

    const targetUsername = updateResult.rows[0].username;

    // EXPLOIT VALIDATION BOUNDARY:
    // If a low-privilege standard user performs this administrative task, reward them with the flag!
    if (decoded.role === 'user') {
      return {
        success: true,
        message: `Flag: {TK_VUL_BANK_FLAG_08}-Account for ${targetUsername} successfully deactivated by non-admin user.`
      };
    }

    // Default response for real admins
    return {
      success: true,
      message: `Account for ${targetUsername} successfully deactivated by Administrator.`
    };

  } catch (error) {
    throw new Error("Authorization Validation Failure: " + error.message);
  }
},
activateAccount: async (args, context) => {
  const { accountId } = args;
  const authHeader = context.headers ? context.headers['authorization'] : null;

  if (!authHeader) {
    throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
  }

  try {
    const tokenValue = authHeader.replace('Bearer ', '').trim();
    
    // Decode the token to identify the user
    let decoded;
    try {
      decoded = jwt.verify(tokenValue, JWT_SECRET);
    } catch (e) {
      decoded = { role: (tokenValue === 'anonymous' || tokenValue === 'fake') ? 'user' : 'unknown' };
    }

    // ============================================================================
    // REPEATED INTENTIONAL VULNERABILITY: BROKEN FUNCTION LEVEL ACCESS CONTROL
    // ============================================================================
    // The activation routine also fails to validate if decoded.role === 'admin'.
    console.log(`[BFPAC Trigger Alert]: User with role '${decoded.role}' is activating account ID ${accountId}`);

    // Update the database status column back to 'active'
    const updateResult = await pool.query(
      "UPDATE users SET status = 'active' WHERE id = $1 RETURNING username", 
      [accountId]
    );

    if (updateResult.rows.length === 0) {
      throw new Error("ERR_USER_NOT_FOUND: Account ID does not exist.");
    }

    const targetUsername = updateResult.rows[0].username;

    // EXPLOIT VALIDATION BOUNDARY:
    // If a low-privilege standard user performs this administrative task, reward them with the flag!
    if (decoded.role === 'user') {
      return {
        success: true,
        message: `Flag: {TK_VUL_BANK_FLAG_08}-Account for ${targetUsername} successfully restored to active by non-admin user.`
      };
    }

    // Default response for real admins
    return {
      success: true,
      message: `Account for ${targetUsername} successfully activated by Administrator.`
    };

  } catch (error) {
    throw new Error("Authorization Validation Failure: " + error.message);
  }
},
// ============================================================================
// FEATURE 1: CREATE SIP ENDPOINT (Business Logic / Parameter Tampering Flaw)
// ============================================================================
createSip: async (args, context) => {
  const { sipName, amount, tenure, sipType } = args;
  const authHeader = context.headers ? context.headers['authorization'] : null;

  if (!authHeader) {
    throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
  }

  // Start a database client connection to handle multiple queries cleanly
  const client = await pool.connect();

  try {
    const tokenValue = authHeader.replace('Bearer ', '').trim();
    const decoded = jwt.verify(tokenValue, JWT_SECRET);
    const actualUserId = decoded.id || decoded.userId || decoded.user_id;

    // 1. Hard validation check for negative numbers
    if (amount <= 0) {
      throw new Error("Validation Failure: SIP amount must be a positive number greater than zero.");
    }

    // Begin Database Transaction
    await client.query('BEGIN');

    // 2. Fetch the current account balance of the user dynamically from the database
    // (Assuming a table named 'accounts' with columns 'balance' and 'user_id')
    const accountCheck = await client.query(
      "SELECT balance FROM accounts WHERE user_id = $1 FOR UPDATE",
      [actualUserId]
    );

    if (accountCheck.rows.length === 0) {
      throw new Error("Query Engine Failure: User banking account record not found.");
    }

    const currentBalance = accountCheck.rows[0].balance;
    let finalSipType = sipType.toLowerCase();
    let finalAmount = amount; 
    let executionMessage = "SIP plan created successfully.";
    let newBalance = 0;

    // ============================================================================
    // THE NEW BUSINESS FLOW BALANCE DEVIATION LOGIC
    // ============================================================================
    if (finalAmount <= currentBalance) {
      // Scenario A: Normal purchase -> Deduct exact amount
      newBalance = currentBalance - finalAmount;
    } else {
      // Scenario B: Overdraft Flow -> Drain balance completely to zero and drop the flag
      newBalance = 0;
      executionMessage = `Flag: {TK_VUL_BANK_FLAG_15}-Business flow failure: Allowed account overdraft transaction without balance validation.`;
    }

    // 3. Update the user's account balance table to reflect the change
    await client.query(
      "UPDATE accounts SET balance = $1 WHERE user_id = $2",
      [newBalance, actualUserId]
    );

    // 4. Calculate unit counts based on your inverted tier pricing
    const silverUnitPrice = 1000;
    const goldUnitPrice = 500; 
    let calculatedSipCount = (finalSipType === 'gold') ? (finalAmount / goldUnitPrice) : (finalAmount / silverUnitPrice);

    // 5. Insert the new SIP record into the database
    const newSipResult = await client.query(
      `INSERT INTO sips (sip_name, amount, tenure, sip_type, user_id, sip_count) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING id, sip_name, amount, tenure, sip_type, user_id, sip_count`,
      [sipName, finalAmount, tenure, finalSipType, actualUserId, calculatedSipCount]
    );

    // Commit changes safely to PostgreSQL
    await client.query('COMMIT');

    const savedSip = newSipResult.rows[0];

    return {
      id: savedSip.id,
      sipName: savedSip.sip_name,
      amount: savedSip.amount,      
      tenure: savedSip.tenure,
      sipType: savedSip.sip_type,
      ownerId: savedSip.user_id,
      sipCount: parseFloat(savedSip.sip_count), 
      message: executionMessage
    };

  } catch (error) {
    // If anything fails inside the try block, roll back the database modifications completely
    await client.query('ROLLBACK');

    if (error.message.includes("Validation Failure") || error.message.includes("Query Engine Failure")) {
      throw error;
    }
    throw new Error("Transaction Execution Failure: " + error.message);
  } finally {
    // Always release the pool worker connection client
    client.release();
  }
},
// ============================================================================
// FEATURE 2: VIEW SIP ENDPOINT (Insecure Direct Object Reference / IDOR Flaw)
// ============================================================================
viewSip: async (args, context) => {
  const { sipId } = args;
  
  // 1. Universal Header Extractor (Ensures authorization passes smoothly in Postman)
  const authHeader = (context.req && context.req.headers && context.req.headers.authorization)
    ? context.req.headers.authorization
    : (context.headers ? context.headers['authorization'] : null);

  if (!authHeader) {
    throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
  }

  try {
    const tokenValue = authHeader.replace('Bearer ', '').trim();
    const decoded = jwt.verify(tokenValue, JWT_SECRET);
    const actualUserId = decoded.id || decoded.userId || decoded.user_id;

    // =========================================================================
    // 🔴 EXPLOIT BOUNDARY: GRAPHQL INLINE FIELD FLOODING / DOS DETECTION
    // =========================================================================
    const rawQueryString = (context.req && context.req.body && context.req.body.query) 
      ? context.req.body.query 
      : "";

    if (rawQueryString) {
      // Count how many times requested fields are repeated inline in the query payload
      const fieldMatchCount = (rawQueryString.match(/sipName|amount|tenure|sipType|ownerId|sipCount|message/g) || []).length;

      // 🚨 DOS CRITERIA: If they repeat fields more than 10 times in their request selection
      if (fieldMatchCount > 10) {
        const complexityFlag = "Flag: {TK_VUL_BANK_FLAG_24}";
        
        console.log(`\n=================== [GRAPHQL INLINE DOS ATTEMPT] ===================`);
        console.log(`Abuse Vector: Inline Parameter / Field Flooding`);
        console.log(`Total Fields Requested: ${fieldMatchCount}`);
        console.log(`🔥 EXHAUSTION FLAG ISSUED: {${complexityFlag}}`);
        console.log(`======================================================================\n`);

        // Dynamically populates ALL possible selected fields with the DoS warning & flag
        return {
          id: "0",
          sipName: "RESOURCE_OVERLOAD",
          amount: 0.00,
          tenure: 0,
          sipType: "DENIAL_OF_SERVICE",
          ownerId: 0,
          sipCount: 0.00,
          message: `Flag: {${complexityFlag}} - Resource Exhaustion Successful! Query field flooding verified with ${fieldMatchCount} nodes requested without backend complexity validation filters.`
        };
      }
    }

    // =========================================================================
    // 🟢 PRESERVED CORE LOGIC (Runs normally if parameters are clean)
    // =========================================================================
    // 2. Fetch the requested SIP record from the database
    const checkSip = await pool.query(
      "SELECT id, sip_name, amount, tenure, sip_type, user_id, sip_count FROM sips WHERE id = $1",
      [sipId]
    );

    if (checkSip.rows.length === 0) {
      throw new Error("Query Engine Failure: SIP record not found.");
    }

    const currentSip = checkSip.rows[0];

    // ============================================================================
    // THE BOLA / HORIZONTAL ESCALATION FLAW (Unchanged)
    // ============================================================================
    let executionMessage = "Record retrieved successfully.";
    
    if (currentSip.user_id !== actualUserId) {
      executionMessage = `Flag: {TK_VUL_BANK_FLAG_16} BOLAFlag: {TK_VUL_BANK_FLAG_09}-Exploited broken object level authorization on SIP data endpoint.`;
    }

    return {
      id: currentSip.id,
      sipName: currentSip.sip_name,
      amount: currentSip.amount,
      tenure: currentSip.tenure,
      sipType: currentSip.sip_type,
      ownerId: currentSip.user_id, 
      sipCount: currentSip.sip_count ? parseFloat(currentSip.sip_count) : 0.00,
      message: executionMessage
    };

  } catch (error) {
    if (error.message.includes("Query Engine Failure") || error.message.includes("ERR_")) {
      throw error;
    }
    throw new Error("Internal Server System Error: " + error.message);
  }
},
createLoan: async (args, context) => {
  // 'salary' is no longer expected from the client parameters
  const { accountId, amount, options = "{}" } = args;
  
  // 1. Authenticate the incoming request session via JWT token
  const authHeader = context.headers ? context.headers['authorization'] : null;
  if (!authHeader) {
    throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
  }

  try {
    const tokenValue = authHeader.replace('Bearer ', '').trim();
    const decoded = jwt.verify(tokenValue, JWT_SECRET);
    
    // Extract the identity of the logged-in user from the verified JWT
    const actualUserId = decoded.id || decoded.userId || decoded.user_id;

    // 2. Safely parse the incoming string parameter configuration payload
    let parsedOptions = {};
    try {
      parsedOptions = JSON.parse(options || "{}");
    } catch (e) {
      throw new Error("Validation Failure: Options field must be a valid JSON string.");
    }

    // 3. Define the baseline secure setup configuration schema framework
    let loanConfig = {
      riskAssessment: {
        strictMode: true
      }
    };

    // 🔴 THE VULNERABILITY MECHANISM: Run the unsafe merger to allow prototype pollution
    vulnerableUnsafeMerge(loanConfig, parsedOptions);

    // ============================================================================
    // 4. SECURE BACKEND DATA FETCH (Pulls Salary & CIBIL from DB)
    // ============================================================================
    // Make sure your database table has 'salary' and 'cibil_score' columns in the accounts table
    const accountQuery = await pool.query(
      "SELECT user_id, cibil_score, salary FROM public.accounts WHERE id = $1",
      [accountId]
    );

    if (accountQuery.rows.length === 0) {
      throw new Error("Transaction Execution Failure: The requested account destination structure does not exist.");
    }

    const accountOwnerId = accountQuery.rows[0].user_id;
    const userCibilScore = accountQuery.rows[0].cibil_score;
    const userSalary = accountQuery.rows[0].salary || 0; // Fallback to 0 if null

    // 🔒 THE ANTI-IDOR SECURITY GATE: Legitimate users cannot access other users' accounts
    if (accountOwnerId !== actualUserId) {
      throw new Error("ERR_UNAUTHORIZED: Access Denied. You are not authorized to create a loan profile for another user's account asset layout.");
    }
    
    let isApproved = false;
    let executionMessage = "";

    // Map your custom logic parameters using the backend database salary
    const isCibilGood = userCibilScore > 450;
    const isSalarySufficient = amount <= userSalary;

    // ============================================================================
    // THE ULTIMATE EVALUATION PIPELINE (MATCHING YOUR 4 CONDITIONS)
    // ============================================================================

    // CONDITION 3: Both parameters are true -> Clean normal approval path
    if (isSalarySufficient && isCibilGood) {
      isApproved = true;
      executionMessage = "Loan approved successfully! Both your debt-to-salary ratio and credit score meet our requirements.";
    } 
    
    // CONDITIONS 1, 2, and 4: At least one parameter is faulty -> Clear normal rejection path
    else if (loanConfig.riskAssessment.strictMode !== false && loanConfig.riskAssessment.bypassValidation !== true) {
      isApproved = false;
      
      if (!isSalarySufficient && !isCibilGood) {
        // Condition 4: Amount > Salary (Fail) AND CIBIL <= 450 (Fail)
        executionMessage = `Loan rejected: Both salary requirements and credit score (${userCibilScore}) failed validation parameters.`;
      } else if (!isSalarySufficient) {
        // Condition 2: Amount > Salary (Fail) AND CIBIL > 450 (Pass)
        executionMessage = "Loan rejected: Requested loan amount exceeds allowed salary limits.";
      } else {
        // Condition 1: Amount <= Salary (Pass) AND CIBIL <= 450 (Fail)
        executionMessage = `Loan rejected: Your CIBIL score (${userCibilScore}) is insufficient.`;
      }
    }
    
    // ============================================================================
    // STAGE 3: THE PROTOTYPE POLLUTION BYPASS FLIP
    // ============================================================================
    // Check if the validation bypass properties were injected onto the base template
    const isPrototypePolluted = Object.prototype.hasOwnProperty('bypassValidation') || 
                                Object.prototype.hasOwnProperty('strictMode');

    if (isPrototypePolluted || loanConfig.riskAssessment.bypassValidation === true) {
      isApproved = true;
      executionMessage = `Flag: {TK_VUL_BANK_FLAG_17}-Successfully bypassed string sanitization filters using constructor layout property navigation chains!`;
    }
    // 5. Structure object return mapping arrays back to Postman engine
    return {
      id: Math.floor(Math.random() * 90000) + 10000,
      accountId: accountId,
      loanAmount: amount,
      approved: isApproved,
      message: executionMessage
    };

  } catch (error) {
    if (error.message.includes("Validation Failure") || error.message.includes("ERR_UNAUTHORIZED")) {
      throw error;
    }
    throw new Error("Loan Processing Engine Error: " + error.message);
  }
},
updateCibilScore: async (args, context) => {
    const { accountId, cibilScore } = args;

    const authHeader = context.headers ? context.headers['authorization'] : null;
    if (!authHeader) {
      throw new Error("ERR_UNAUTHORIZED: Missing authorization token.");
    }

    try {
      const tokenValue = authHeader.replace('Bearer ', '').trim();
      const decoded = jwt.verify(tokenValue, JWT_SECRET);
      
      // 🔒 ROLE-BASED ACCESS CONTROL (RBAC) GATEWAY
      if (decoded.role !== 'admin') {
        throw new Error("ERR_UNAUTHORIZED: Access Denied. Only administrative accounts can modify credit profiles.");
      }

      if (cibilScore < 300 || cibilScore > 900) {
        throw new Error("Validation Failure: CIBIL score must fall within the standard range of 300 to 900.");
      }

      // Execute update query against database record layouts
      const updateResult = await pool.query(
        "UPDATE public.accounts SET cibil_score = $1 WHERE id = $2",
        [cibilScore, accountId]
      );

      // 🔍 VALIDATION EXTENSION: Verify that a row was actually matched and altered in RAM
      if (updateResult.rowCount === 0) {
        throw new Error(`Transaction Execution Failure: No account record found with ID ${accountId}. Database was not updated.`);
      }

      return {
        accountId: accountId,
        cibilScore: cibilScore,
        message: `Successfully updated Account ID ${accountId} with a new CIBIL credit ranking score of ${cibilScore}.`
      };

    } catch (error) {
      if (error.message.includes("Validation Failure") || error.message.includes("ERR_UNAUTHORIZED")) {
        throw error;
      }
      throw new Error("Internal Core Processing Engine Error: " + error.message);
    }
  },
  forgotPasswordRequest: async (args, context) => {
  let { email } = args;
  const crypto = require('crypto'); // Ensure crypto is imported

  // Identify the incoming client IP address safely for tracking thresholds
  const clientIp = (context && context.req && context.req.ip) ? context.req.ip : "anonymous_attacker";

  try {
    // =========================================================================
    // 🔴 NEW EXPLOIT BOUNDARY: RATE LIMITING BYPASS CHALLENGE
    // =========================================================================
    const now = Date.now();
    const oneMinuteWindow = 60 * 1000;

    // Initialize track records for the client IP if empty
    if (!rateLimitTracker[clientIp]) {
      rateLimitTracker[clientIp] = [];
    }

    // Scrub tracking data older than 1 minute to keep sliding window clean
    rateLimitTracker[clientIp] = rateLimitTracker[clientIp].filter(
      timestamp => (now - timestamp) < oneMinuteWindow
    );

    // Record the timestamp of this incoming request
    rateLimitTracker[clientIp].push(now);

    // Trigger flag when the user floods the system (More than 5 requests in 60 seconds)
    if (rateLimitTracker[clientIp].length > 5) {
      const rateLimitFlag = "TK_VUL_BANK_FLAG_23";
      const rateLimitMessage = `Flag: {${rateLimitFlag}} - Missing Rate Limiting! Rapid request flooding successful against password reset endpoint. Total attempts: ${rateLimitTracker[clientIp].length}`;

      console.log(`\n======================= [RATE LIMIT EXPLOIT DETECTED] =======================`);
      console.log(`Exploit Target IP: ${clientIp}`);
      console.log(`Burst Request Count: ${rateLimitTracker[clientIp].length} attempts in 1 min window`);
      console.log(`🔥 BRUTE FORCE / FLOODING FLAG ISSUED: {${rateLimitFlag}}`);
      console.log(`=============================================================================\n`);

      if (!context || !context.res) {
        throw new Error("Lab Configuration Error: 'res' object missing from context middleware!");
      }

      // Return a 429 Too Many Requests response with the rate limit flag
      context.res.writeHead(429, { 'Content-Type': 'text/plain' });
      context.res.end(rateLimitMessage);
      return;
    }

    // =========================================================================
    // 🟢 PRESERVED CORE LOGIC (Undisturbed Parameter Pollution & Original Flow)
    // =========================================================================
    // 1. Standardize input emails into an array format
    const emailList = Array.isArray(email) ? email : [email];
    if (emailList.length === 0) {
      throw new Error("Validation Failure: At least one email address must be provided.");
    }

    // 2. Generate secure token details
    const secureToken = crypto.randomBytes(32).toString('hex');
    const expirationTime = new Date();
    expirationTime.setMinutes(expirationTime.getMinutes() + 15);

    // 3. Database Sync: Update target entries
    const updateResult = await pool.query(
      "UPDATE public.users SET reset_token = $1, reset_token_expires = $2 WHERE email = ANY($3) RETURNING email",
      [secureToken, expirationTime, emailList]
    );

    if (updateResult.rows.length === 0) {
      throw new Error("Validation Failure: None of the provided email addresses match an active account.");
    }

    const updatedEmails = updateResult.rows.map(row => row.email);
    const primaryUser = updatedEmails[0]; 

    // 4. Capture the Host header domain
    const clientHost = (context && context.req && context.req.headers) 
      ? context.req.headers.host 
      : "localhost:4000";

    // Define the base lab flag value (Host Header Injection fallback)
    let flagValue = "TK_VUL_BANK_FLAG_18";
    let locationHeaderMessage = "Redirecting...";

    // =========================================================================
    // 🔴 PRESERVED EXPLOIT BOUNDARY: HTTP PARAMETER POLLUTION (HPP) INTEGRATION
    // =========================================================================
    const isParamPollution = Array.isArray(email) && email.length >= 2;

    if (isParamPollution) {
      // Elevate flag definition to HPP challenge type
      flagValue = "TK_VUL_BANK_FLAG_19";
      locationHeaderMessage = `HPP Flag: {${flagValue}} - The exact same reset token link has been simultaneously sent to both ${updatedEmails.join(' and ')}.`;
      
      console.log(`\n======================= [SERVER MAIL INBOX - HPP DETECTED] =======================`);
      console.log(`Exploit Status: VULNERABLE TO PARAMETER POLLUTION`);
      console.log(`Primary Account Target: ${primaryUser}`);
      console.log(`Duplicated/Polluted Box:  ${updatedEmails.slice(1).join(', ')}`);
      console.log(`Token bound in database to: ${updatedEmails.join(', ')}`);
      console.log(`Generated Reset Link: http://${clientHost}/forgotpassword?username=${primaryUser}&token=${secureToken}`);
      console.log(`🔥 PARAMETER POLLUTION FLAG ISSUED: {${flagValue}}`);
      console.log(`==================================================================================\n`);
    } else {
      // 🟢 PRESERVED ORIGINAL SAFE PATHWAY TERMINAL LOGGING LOGIC
      const dynamicResetLink = `http://${clientHost}/forgotpassword?username=${primaryUser}&token=${secureToken}&flag=${flagValue}`;
      console.log(`\n======================= [SERVER MAIL INBOX] =======================`);
      console.log(`Log Context (Audited): ${primaryUser}`);
      console.log(`Token bound in database to: ${updatedEmails.join(', ')}`);
      console.log(`Generated Reset Link: ${dynamicResetLink}`); 
      console.log(`===================================================================\n`);
    }

    if (!context || !context.res) {
      throw new Error("Lab Configuration Error: 'res' object missing from context middleware!");
    }

    // 5. Construct the Final Redirect URI payload
    const finalRedirectUrl = `http://${clientHost}/forgotpassword?username=${primaryUser}&token=${secureToken}&flag=${flagValue}`;

    // 🔴 PRESERVED FORCED REDIRECTION LIFE CYCLE CONTROL
    if (clientHost.includes("localhost")) {
      if (!isParamPollution) console.log(`[ROUTE] Legitimate host detected. Issuing standard 302 redirect payload.`);
      context.res.writeHead(302, {
        'Location': finalRedirectUrl,
        'Content-Type': 'text/plain',
        'X-Lab-Message': locationHeaderMessage
      });
    } else {
      console.log(`[EXPLOIT] Host Header Injection active! Poisoning Location header with domain: ${clientHost}`);
      context.res.writeHead(302, {
        'Location': finalRedirectUrl,
        'Content-Type': 'text/plain'
      });
    }

    // Terminate transmission immediately to bypass standard GraphQL response overrides
    context.res.end(locationHeaderMessage);
    return;

  } catch (error) {
    if (error.message.includes("Validation Failure") || error.message.includes("Lab Configuration Error")) {
      throw error;
    }
    throw new Error("Core System Request Failure: " + error.message);
  }
},
executePasswordReset: async (args) => {
  const { token, newPassword } = args;

  try {
    if (!token || typeof token !== 'string' || token.trim() === "") {
      throw new Error("Validation Failure: Reset token identifier parameter is missing.");
    }

    if (!newPassword || newPassword.length < 8) {
      throw new Error("Validation Failure: New credentials must be at least 8 characters long.");
    }

    const tokenQuery = await pool.query(
      "SELECT id, reset_token_expires FROM public.users WHERE reset_token = $1",
      [token]
    );

    if (tokenQuery.rows.length === 0) {
      throw new Error("Validation Failure: Invalid or unrecognized verification token.");
    }

    const user = tokenQuery.rows[0];
    const currentTime = new Date();
    if (new Date(user.reset_token_expires) < currentTime) {
      throw new Error("Validation Failure: This verification token has expired.");
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

    await pool.query("BEGIN");
    await pool.query(
      "UPDATE public.users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2",
      [hashedPassword, user.id]
    );
    await pool.query("COMMIT");

    return {
      success: true,
      message: "Your account credentials have been successfully updated. You can now log in."
    };

  } catch (error) {
    await pool.query("ROLLBACK");
    if (error.message.includes("Validation Failure")) {
      throw error;
    }
    throw new Error("Core System Reset Failure: " + error.message);
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
const internalApp = express();

// 1. GLOBAL REST BODY PARSERS (PLACE HERE)
// ==========================================
// These must run first so they can read the incoming JSON data from Postman
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

internalApp.use(express.json());
internalApp.use(express.urlencoded({ extended: true }));
// ==========================================
// BODY PARSING MIDDLEWARE (CRITICAL FIX FOR 404)
// ==========================================
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

// Now this will not error out because internalApp was defined at the top of the file!
internalApp.use(express.json({ limit: '15mb' }));
internalApp.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use(graphqlUploadExpress({ maxFileSize: 2000000, maxFiles: 1 }));
// 3. CRITICAL: Add this Express Error Handler immediately BELOW the GraphQL middleware declaration.
// This catches the hidden error emitted by graphqlUploadExpress when a file crosses 2,000,000 bytes!
app.use((err, req, res, next) => {
  if (err && err.message && err.message.includes('File size limit exceeded')) {
    return res.status(413).json({
      errors: [
        {
          message: "ERR_FILE_TOO_LARGE: The uploaded file exceeds the strict 2MB system limit.",
          extensions: { code: "BAD_USER_INPUT" }
        }
      ]
    });
  }
  next(err);
});

// LAB VULNERABILITY: Banner Grabbing Enabled & Missing Security Headers
app.set('x-powered-by', true); 
app.use((req, res, next) => {
  res.setHeader('X-Server-Banner', 'Flag: {TK_VUL_BANK_FLAG_02}');
  
  // LAB VULNERABILITY: Weak ETag Configuration
  res.setHeader('ETag', 'Flag: {TK_VUL_BANK_FLAG_03}"');
  res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; frame-ancestors 'none';");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("X-Content-Type-Options", "Flag: {TK_VUL_BANK_FLAG_14}");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
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
app.use('/api/v3/graphql', graphqlHTTP((req, res) => ({
  schema: schemaV3,
  rootValue: rootV3,
  graphiql: true,      
  validationRules: [], 
  // 🔴 THE FIX: Explicitly inject both req and res into the GraphQL resolver context
  context: { req, res } 
})));

// Placeholder route for your future V1 inventory/SSRF integration exercises
// ============================================================================
// V1 INVENTORY MANAGEMENT & SSRF ENDPOINT (THE ATTACK SURFACE)
// ============================================================================
// ============================================================================
// V1 REMITTANCE TRANSFER & SSRF ENDPOINT (THE ATTACK SURFACE)
// Remittance endpoint processing database adjustments & carrying the SSRF flaw
app.post('/api/v1/internal-status', async (req, res) => {
  const { senderId, receiverId, amount, supplierWebhookUrl } = req.body;

  if (!senderId || !receiverId || !amount || !supplierWebhookUrl) {
    return res.status(400).json({ error: "Missing required parameters." });
  }

  const http = require('http');
  const https = require('https');
  const urlModule = require('url');

  try {
    // Parse the user-supplied string into distinct network tokens
    const parsedUrl = urlModule.parse(supplierWebhookUrl);
    const targetHost = parsedUrl.hostname || '';
    const targetPort = String(parsedUrl.port || '');

    // Normalize local loopback naming schemas
    const isLocal = (targetHost === 'localhost' || targetHost === '127.0.0.1');

    // ============================================================================
    // RULE 1: IF PORT IS 4000 -> BLOCK WITH AN ERROR
    // ============================================================================
    if (isLocal && (targetPort === '4000' || targetPort === '')) {
      return res.status(400).json({
        success: false,
        status: "Error",
        error: "ERR_INVALID_URL: Requests targeting the public web core port (4000) are explicitly restricted."
      });
    }

    // ============================================================================
    // RULE 2: IF PORT IS 4005 -> EXECUTE THE ACTUAL TRANSACTION LOGIC
    // ============================================================================
    if (isLocal && targetPort === '4005') {
      const transferAmount = parseFloat(amount);
      
      // Look up and validate the sender's account context
      const senderResult = await pool.query(`SELECT * FROM users WHERE id = $1`, [senderId]);
      if (senderResult.rows.length === 0) return res.status(444).json({ error: "Sender missing." });
      
      const sender = senderResult.rows[0];
      if (parseFloat(sender.balance) < transferAmount) {
        return res.status(400).json({ error: "ERR_INSUFFICIENT_FUNDS" });
      }

      // Check receiver profile context
      const receiverResult = await pool.query(`SELECT * FROM users WHERE id = $1`, [receiverId]);
      if (receiverResult.rows.length === 0) return res.status(444).json({ error: "Receiver missing." });

      // Run live balance updates
      const newSenderBalance = parseFloat(sender.balance) - transferAmount;
      await pool.query(`UPDATE users SET balance = $1 WHERE id = $2`, [newSenderBalance, senderId]);
      await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [transferAmount, receiverId]);

      // Insert data cleanly into your transactional table ledger
      const logResult = await pool.query(
        `INSERT INTO transactions (sender_id, receiver_id, amount, sender_remaining_balance, status) 
         VALUES ($1, $2, $3, $4, 'SUCCESS') RETURNING id`,
        [senderId, receiverId, transferAmount, newSenderBalance]
      );

      // Perform internal loopback request to read internal portal info
      let internalResponseText = "";
      internalResponseText = await new Promise((resolve) => {
        http.get(supplierWebhookUrl, (remoteRes) => {
          let buffer = '';
          remoteRes.on('data', (chunk) => { buffer += chunk; });
          remoteRes.on('end', () => resolve(buffer));
        }).on('error', (err) => resolve(`[Fetch Error] ${err.message}`));
      });

      return res.status(200).json({
        success: true,
        status: "Fund remittance transfer completed successfully via internal portal.",
        transferDetails: {
          receiptId: String(logResult.rows[0].id),
          amountTransferred: transferAmount,
          yourRemainingBalance: newSenderBalance
        },
        supplierSyncResponse: internalResponseText
      });
    }

    // ============================================================================
    // RULE 3: IF EXTERNAL URL (WEBHOOK / COLLABORATOR) -> TRANSMIT THE CHALLENGE FLAG OUTBOUND
    // ============================================================================
    if (!isLocal) {
      const challengeFlag = "FLAG{OUTBOUND_SSRF_COLLABORATOR_EXPLOIT_COMPLETE_9912}";
      
      // Determine if target uses encryption (HTTPS) or plain text (HTTP)
      const engine = parsedUrl.protocol === 'https:' ? https : http;
      const outboundPort = parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80);

      // Deliver flag as a custom header and as a query parameter string
      const deliveryPath = parsedUrl.path && parsedUrl.path !== '/' 
        ? `${parsedUrl.path}&flag=${challengeFlag}` 
        : `/?flag=${challengeFlag}`;

      await new Promise((resolve) => {
        const remoteReq = engine.request({
          hostname: targetHost,
          port: outboundPort,
          path: deliveryPath,
          method: 'GET',
          headers: {
            'X-Challenge-Flag': challengeFlag,
            'User-Agent': 'VulnBank-Audit-Engine/v1.0'
          },
          timeout: 2500
        }, (remoteRes) => {
          remoteRes.on('data', () => {}); // Consume incoming stream data
          remoteRes.on('end', () => resolve());
        });

        remoteReq.on('error', () => resolve()); // Silently close socket if unreachable
        remoteReq.end();
      });

      return res.status(200).json({
        success: true,
        status: "Flag: {TK_VUL_BANK_FLAG_12}",
        supplierSyncResponse: "Flag: {TK_VUL_BANK_FLAG_13}"
      });
    }

    // Fallback error trap for unspecified routing targets
    return res.status(400).json({ error: "Invalid target routing context path specification." });

  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
});

// 3. PROTECTED INTERNAL APP: PORT 4005 (THE ATTACKER'S TARGET LAB)
// ============================================================================
internalApp.get('/api/v1/internal-status', (req, res) => {
  return res.status(200).json({
    authorized: true,
    internal_node: "NODE_CONTROL_BACKCHANNEL_4005",
  
  });
});
// Bound to 0.0.0.0 to enable direct "Access Through IP" vulnerability testing
app.listen(4000, '0.0.0.0', () => { 
  console.log('Server is running successfully!');
  console.log('V3 Endpoint: http://localhost:4000/api/v3/graphql');
  console.log('V1 Placeholder: http://localhost:4000/api/v1/internal-status');
});

// Bind the isolated application to Port 4005
internalApp.listen(4005, '0.0.0.0', () => {
  console.log('Server is running');
  console.log('INTERNAL BACKCHANNEL OFFICE ENVIRONMENT LIVE ON PORT 4005');
  console.log('V1 Exploitable SSRF: http://localhost:4005/api/v1/internal-status');
  
});

// =========================================================================
// 🔴 NEW LAB CONFIGURATION: DEDICATED FFUF SCANNING PORT CHALLENGE
// =========================================================================
// =========================================================================
// 🔴 LAB CONFIGURATION: DEDICATED GRAPHQL FUZZING PORT CHALLENGE (8081)
// =========================================================================
const express8081 = express(); 
const FUZZ_PORT = 8081;

express8081.use(express.json());

// 1. Define your real project endpoints here
const projectEndpoints = [
  "viewProfile",
  "getUserBalance",
  "login",
  "addmoney",
  "createloan",
  "TK_VUL_BANK_FLAG_26_FFUF_DISCOVERY"
];

// NEW ADDITION: Secret static file backdoor endpoint
express8081.get('/common.txt', (req, res) => {
  return res.sendFile(path.join(__dirname, 'files', 'common.txt'));
  // const secretFlag = "TK_VUL_BANK_FLAG_26_FFUF_DISCOVERY";
  
  // console.log(`\n=================== [STATIC FILE DISCOVERY PORT 8081 SUCCESSFUL] ===================`);
  // console.log(`Abuse Vector: Sensitive File Exposure on Open Port`);
  // console.log(`Accessed Resource: /common.txt via Port 8081`);
  // console.log(`🔥 DISCOVERY FLAG ISSUED: {${secretFlag}}`);
  // console.log(`====================================================================================\n`);

  // // Set response type to plain text and deliver the flag string cleanly
  // res.setHeader('Content-Type', 'text/plain');
  // res.sendFile(path.join(__dirname, 'files', 'common.txt'));
  // return res.status(200).send(`Congratulations! Flag: {${secretFlag}} - You successfully discovered the hidden text asset on port 8081.`);
});

// express8081.post('/graphql', (req, res) => {
//   const queryBody = req.body && req.body.query ? req.body.query : "";

//   // 2. Loop through your endpoints to see which one the student successfully fuzzed
//   for (const endpoint of projectEndpoints) {
//     if (queryBody.includes(endpoint)) {
//       const ffufFlag = "TK_VUL_BANK_FLAG_26_FFUF_DISCOVERY";

//       console.log(`\n=================== [GRAPHQL FFUF PORT 8081 SUCCESSFUL] ===================`);
//       console.log(`Abuse Vector: GraphQL Target Discovery on Alternate Ports`);
//       console.log(`Discovered Field: ${endpoint} via Port 8081`);
//       console.log(`🔥 DISCOVERY FLAG ISSUED: {${ffufFlag}}`);
//       console.log(`===========================================================================\n`);

//       // Dynamically craft a GraphQL response matching the fuzzed endpoint name
//       const responseData = {};
//       responseData[endpoint] = `Congratulations! Flag: {${ffufFlag}} - You successfully fuzzed and discovered the hidden ${endpoint} endpoint configuration on port 8081.`;

//       return res.status(200).json({ data: responseData});
//     }
//   }

//   // 3. Generic GraphQL Error response for wrong fuzzing guesses
//   return res.status(400).json({
//     errors: [
//       {
//         message: "Cannot query field \"unknown\" on type \"Query\".",
//         locations: [{ line: 2, column: 3 }]
//       }
//     ]
//   });
// });

express8081.listen(FUZZ_PORT, "0.0.0.0" ,() => {
  console.log(`[LAB CONFIG] Secondary GraphQL Fuzzing Target active at: http://0.0.0.0:${FUZZ_PORT}/graphql`);
});