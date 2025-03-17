const express = require('express');
const axios = require('axios');
const qs = require('querystring');
const session = require('express-session');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const app = express();
const rateLimit = require('express-rate-limit');

// Hardcoded credentials (for testing purposes, don't judge me!!)
const CLIENT_ID = '######';
const CLIENT_SECRET = '######';
const REDIRECT_URI = 'Callback_uri';
const SESSION_SECRET = '######';

// Hardcoded VRChat Service Account credentials (use environmental variables for production)
const SERVICE_USERNAME = 'Username_Here';
const SERVICE_PASSWORD = 'Password_Here';

// Configure session middleware
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
}));

// Use body-parser for URL-encoded form data and JSON bodies.
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Configure Express to use EJS (for rendering dashboard)
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// Create a MySQL connection pool
// Note: Here, "discord id" refers to the unique tag that you want to store (the one stored in your SQL database).
const pool = mysql.createPool({
    host: 'localhost',
    user: 'Username',           // Replace with your MySQL user
    password: 'Password',     // Your MySQL password
    database: 'database_name',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Limit each IP to 5 requests per 10 minutes (for VRChat binding verification)
const verifyVrcLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    message: "Too many attempts to bind VRChat account. Please refresh your dashboard in 10 minutes. If nothing has appeared, you may try again.",
    standardHeaders: true,
    legacyHeaders: false,
});

// Directory for group moderator JSON files
const groupModsDir = path.join(__dirname, 'groupmods');
// Ensure the groupmods directory exists
if (!fs.existsSync(groupModsDir)) {
    fs.mkdirSync(groupModsDir);
}

/**
 * Helper function to scan the /groupmods directory.
 * For each file, if the stored object (which includes a "moderators" array and a "name" field)
 * contains the user's discord tag (the unique value stored in SQL), then that group is added.
 */
function processManualModerators(userDiscordTag, callback) {
    const moderatedGroups = [];
    fs.readdir(groupModsDir, (err, files) => {
        if (err) {
            console.error("Error reading groupmods directory:", err);
            return callback([]);
        }
        if (files.length === 0) return callback([]);
        let filesProcessed = 0;
        files.forEach(file => {
            const groupId = path.basename(file, '.json');
            const filePath = path.join(groupModsDir, file);
            fs.readFile(filePath, 'utf8', (err, data) => {
                filesProcessed++;
                if (!err) {
                    try {
                        const fileData = JSON.parse(data);
                        let moderatorsArray = [];
                        let groupName = groupId; // default value if no name provided
                        if (typeof fileData === 'object' && !Array.isArray(fileData)) {
                            moderatorsArray = fileData.moderators || [];
                            groupName = fileData.name || groupId;
                        } else {
                            moderatorsArray = fileData;
                        }
                        if (moderatorsArray.includes(userDiscordTag)) {
                            moderatedGroups.push({ groupId, name: groupName });
                        }
                    } catch (e) {
                        console.error("Error parsing moderator file:", file, e);
                    }
                }
                if (filesProcessed === files.length) {
                    callback(moderatedGroups);
                }
            });
        });
    });
}

// Function to create or update a user in the database.
// "discord id" here means the unique tag that you wish to store.
function createOrUpdateUser(discordUser, callback) {
    const sql = `
    INSERT INTO users (discord_id, username)
    VALUES (?, ?)
    ON DUPLICATE KEY UPDATE username = VALUES(username)
  `;
    pool.query(sql, [discordUser.id, discordUser.username], (err, results) => {
        if (err) return callback(err);
        callback(null, results);
    });
}

// Function to update a user's VRChat binding in the database.
function bindVRCAcc(sessionUserTag, vrcLink, callback) {
    const sql = `
    UPDATE users SET vrc_link = ? WHERE discord_id = ?
  `;
    pool.query(sql, [vrcLink, sessionUserTag], (err, results) => {
        if (err) {
            console.error("Database Error:", err);
            return callback(err);
        }
        console.log("Successfully updated VRChat user id for discord tag:", sessionUserTag, "as:", vrcLink);
        callback(null, results);
    });
}

// ------------------
// Discord OAuth Flow
// ------------------

// Redirect user to Discord's OAuth2 authorization URL
app.get('/auth/discord', (req, res) => {
    const params = qs.stringify({
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'identify'
    });
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize?${params}`;
    res.redirect(discordAuthUrl);
});

// Handle the OAuth2 callback from Discord
app.get('/auth/discord/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.redirect('/login');
    }
    try {
        // Exchange the authorization code for an access token
        const tokenResponse = await axios.post(
            'https://discord.com/api/oauth2/token',
            qs.stringify({
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: REDIRECT_URI
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        const { access_token } = tokenResponse.data;

        // Fetch user data from Discord
        const userResponse = await axios.get('https://discord.com/api/users/@me', {
            headers: { Authorization: `Bearer ${access_token}` }
        });
        const discordUser = userResponse.data;

        // Use global_name if available; otherwise, fallback to username.
        // This value will serve as the unique tag we store in our SQL database.
        const uniqueDiscordName = discordUser.username;

        // Create or update the user record in MySQL.
        // We store uniqueDiscordName as the discord_id.
        createOrUpdateUser({ id: uniqueDiscordName, username: discordUser.username }, (err, results) => {
            if (err) {
                console.error("Database Error:", err);
                return res.redirect('/failedLogin');
            }
            // Save both the numeric Discord id and the uniqueDiscordName in the session.
            req.session.user = {
                id: discordUser.id, // numeric id
                discordTag: uniqueDiscordName, // unique tag for our purposes
                avatar: discordUser.avatar
                    ? `https://cdn.discordapp.com/avatars/${discordUser.id}/${discordUser.avatar}.png`
                    : 'https://cdn.discordapp.com/embed/avatars/0.png'
            };
            res.redirect('/dashboard');
        });
    } catch (error) {
        console.error("Discord OAuth Error:", error.response ? error.response.data : error.message);
        res.redirect('/login');
    }
});

// -----------------------
// Protected Dashboard Route
// -----------------------
// This route uses the session's user tag to fetch the user's VRChat link.
// It then loads the owned groups from a cached JSON file (if available)
// and scans /groupmods for moderated groups.
app.get('/dashboard', async (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const verificationPending = req.session.verificationPending || false;
    const verificationResult = req.session.verificationResult || null;
    delete req.session.verificationPending;
    delete req.session.verificationResult;

    // Use the unique discord tag stored in the session.
  // god damnit discord why do you have 'username' and 'tag' and 'global_username' separated without documentation, i don't know what global means!!!
    const discordTag = req.session.user.discordTag;

    pool.query('SELECT vrc_link FROM users WHERE discord_id = ?', [discordTag], (err, results) => {
        if (err || results.length === 0 || !results[0].vrc_link) {
            // User hasn't bound a VRChat account.
            return res.render('dashboard', {
                user: req.session.user,
                ownedGroups: [],
                moderatedGroups: [],
                verificationPending,
                verificationResult,
                vrcLinked: false,
                groupsCached: false
            });
        }

        const groupsFilePath = path.join(__dirname, 'usergroups', `${discordTag}.json`);

        fs.access(groupsFilePath, fs.constants.F_OK, (err) => {
            if (err) {
                // File doesn't exist: set ownedGroups as empty.
                const ownedGroups = [];
                const groupsCached = false;
                processManualModerators(discordTag, (moderatedGroups) => {
                    res.render('dashboard', {
                        user: req.session.user,
                        ownedGroups,
                        moderatedGroups,
                        verificationPending,
                        verificationResult,
                        vrcLinked: true,
                        groupsCached
                    });
                });
            } else {
                // File exists; read and parse the JSON.
                fs.readFile(groupsFilePath, 'utf8', (err, data) => {
                    let ownedGroups = [];
                    let groupsCached = false;
                    if (err) {
                        console.error("Error reading groups file:", err);
                    } else {
                        try {
                            ownedGroups = JSON.parse(data);
                            groupsCached = true;
                        } catch (e) {
                            console.error("Error parsing groups file:", e);
                        }
                    }
                    processManualModerators(discordTag, (moderatedGroups) => {
                        res.render('dashboard', {
                            user: req.session.user,
                            ownedGroups,
                            moderatedGroups,
                            verificationPending,
                            verificationResult,
                            vrcLinked: true,
                            groupsCached
                        });
                    });
                });
            }
        });
    });
});

// -----------------------
// Update Owned Groups Route
// -----------------------
// This route fetches the latest groups from the VRChat API and saves them as a JSON file.
app.get('/update-groups', async (req, res) => {
    if (!req.session.user) return res.redirect('/');

    const discordTag = req.session.user.discordTag;
    pool.query('SELECT vrc_link FROM users WHERE discord_id = ?', [discordTag], async (err, results) => {
        if (err || results.length === 0 || !results[0].vrc_link) {
            return res.redirect('/dashboard');
        }
        const vrcUserId = results[0].vrc_link;
        try {
            const apiResponse = await axios.post('https://fch-toolkit.com/get-vrc-groups', { vrcUserId });
            let ownedGroups = apiResponse.data.ownedGroupsList || [];
            ownedGroups = ownedGroups.map(group => ({
                groupId: group.groupId,
                name: group.name,
                avatarUrl: group.iconUrl || '/default-avatar.png',
                bannerUrl: group.bannerUrl || '/default-banner.jpg'
            }));

            // Ensure the usergroups directory exists.
            const usergroupsDir = path.join(__dirname, 'usergroups');
            if (!fs.existsSync(usergroupsDir)) {
                fs.mkdirSync(usergroupsDir);
            }

            // Write to file using the user's unique discord tag.
            const groupsFilePath = path.join(usergroupsDir, `${discordTag}.json`);
            fs.writeFile(groupsFilePath, JSON.stringify(ownedGroups, null, 2), (err) => {
                if (err) {
                    console.error("Error writing groups file:", err);
                }
                return res.redirect('/dashboard');
            });
        } catch (apiErr) {
            console.error("API error:", apiErr);
            return res.redirect('/dashboard');
        }
    });
});

// -----------------------
// VRChat Binding Flow
// -----------------------
// Display the VRChat binding form.
app.get('/bind-vrc', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <title>Bind VRChat Account - FCH Toolkit</title>
      <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap" rel="stylesheet">
      <style>
        body {
          background-color: #121212;
          color: #e0e0e0;
          font-family: 'Poppins', sans-serif;
          margin: 0;
          padding: 0;
        }
        .container {
          max-width: 1040px;
          margin: 80px auto 20px;
          padding: 20px;
          text-align: center;
        }
        h1 {
          font-size: 40px;
          margin-bottom: 20px;
        }
        form {
          max-width: 500px;
          margin: 0 auto;
        }
        label {
          font-size: 1.2rem;
          margin-bottom: 10px;
          display: block;
        }
        input {
          width: 100%;
          padding: 10px;
          font-size: 1rem;
          margin-bottom: 20px;
          border: 1px solid #333;
          border-radius: 5px;
          background: #1a1a1a;
          color: #e0e0e0;
        }
        button {
          background-color: #333;
          color: #e0e0e0;
          padding: 10px 20px;
          border: none;
          border-radius: 5px;
          cursor: pointer;
          font-size: 1.2rem;
        }
        button:hover {
          background-color: #444;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Bind Your VRChat Account</h1>
        <form action="/bind-vrc" method="POST">
          <label>Enter your VRChat account link:</label>
          <input type="text" name="vrcLink" placeholder="https://vrchat.com/home/user/usr_..." required />
          <button type="submit">Submit</button>
        </form>
      </div>
    </body>
    </html>
  `);
});

app.post('/bind-vrc', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const vrcLink = req.body.vrcLink;
    const regex = /^https:\/\/vrchat\.com\/home\/user\/(usr_[a-f0-9-]+)$/;
    const match = vrcLink.match(regex);
    if (!match) return res.status(400).send("Invalid URL");
    const vrcUserId = match[1];
    const verificationCode = crypto.randomBytes(4).toString('hex'); // Generates random verification code
    // Store temporary verification details in user's session.
    req.session.vrcVerification = { vrcUserId, verificationCode };
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Verify VRChat Account - FCH Toolkit</title>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;700&display=swap" rel="stylesheet">
        <style>
          body {
            background-color: #121212;
            color: #e0e0e0;
            font-family: 'Poppins', sans-serif;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 1040px;
            margin: 80px auto 20px;
            padding: 20px;
            text-align: center;
          }
          h2 {
            margin-bottom: 20px;
          }
          h1 {
            color: #ffb6c1;
            font-family: 'Grechen Fuemen', fantasy;
            font-size: 60px;
            margin-bottom: 20px;
          }
          h3 {
            margin-bottom: 30px;
          }
          button {
            background-color: #333;
            color: #ffb6c1;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1.2rem;
          }
          button:hover {
            background-color: #444;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h2>Set your VRChat status to this code:</h2>
          <h1>${verificationCode}</h1>
          <h3>Database may take several minutes to update.</h3>
          <form action="/verify-vrc-status" method="POST">
            <button type="submit">I've set my status</button>
          </form>
        </div>
      </body>
      </html>
    `);
});

app.all('/verify-vrc-status', verifyVrcLimiter, async (req, res) => {
    if (!req.session.user || !req.session.vrcVerification) return res.redirect('/dashboard');
    const { vrcUserId, verificationCode } = req.session.vrcVerification;
    const sessionUserTag = req.session.user.discordTag;
    try {
        const apiResp = await axios.post('http://localhost:4000/get-vrc-status', { vrcUserId });
        const { statusDescription } = apiResp.data;
        if (statusDescription.trim() === verificationCode) {
            // Bind the VRChat account in the database.
            await new Promise(resolve => {
                bindVRCAcc(sessionUserTag, vrcUserId, (err) => {
                    if (err) {
                        console.error("Database error:", err);
                        req.session.verificationResult = 'error';
                    } else {
                        req.session.verificationResult = 'success';
                    }
                    resolve();
                });
            });
            // If binding was successful, fetch groups and write the JSON file.
            if (req.session.verificationResult === 'success') {
                try {
                    const groupsResp = await axios.post('https://fch-toolkit.com/get-vrc-groups', { vrcUserId });
                    let ownedGroups = groupsResp.data.ownedGroupsList || [];
                    ownedGroups = ownedGroups.map(group => ({
                        groupId: group.groupId,
                        name: group.name,
                        avatarUrl: group.iconUrl || '/default-avatar.png',
                        bannerUrl: group.bannerUrl || '/default-banner.jpg'
                    }));
                    const usergroupsDir = path.join(__dirname, 'usergroups');
                    if (!fs.existsSync(usergroupsDir)) {
                        fs.mkdirSync(usergroupsDir);
                    }
                    const groupsFilePath = path.join(usergroupsDir, `${sessionUserTag}.json`);
                    fs.writeFile(groupsFilePath, JSON.stringify(ownedGroups, null, 2), (err) => {
                        if (err) {
                            console.error("Error writing groups file:", err);
                        } else {
                            console.log("Owned groups file created at:", groupsFilePath);
                        }
                    });
                } catch (groupErr) {
                    console.error("Error fetching or writing owned groups:", groupErr);
                }
            }
        } else {
            req.session.verificationResult = 'mismatch';
        }
    } catch (err) {
        console.error("API error:", err.message);
        req.session.verificationResult = 'error';
    } finally {
        delete req.session.vrcVerification;
        req.session.save();
        res.redirect('/dashboard');
    }
});

// -----------------------
// New Endpoints for Moderator Functionality
// -----------------------

// GET /get-moderators: Reads the moderator JSON file for the given group and returns the moderators array.
// Accepts an optional groupName query parameter; when a file is first created, it stores that name.
app.get('/get-moderators', (req, res) => {
    const groupId = req.query.groupId;
    const groupName = req.query.groupName; // optional: if provided, used when file is created
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });
    const filePath = path.join(groupModsDir, `${groupId}.json`);
    if (!fs.existsSync(filePath)) {
        const newFileData = { name: groupName || "", moderators: [] };
        fs.writeFileSync(filePath, JSON.stringify(newFileData, null, 2));
        return res.json([]);
    }
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error("Error reading moderator file:", err);
            return res.status(500).json({ error: 'Server error' });
        }
        try {
            const fileData = JSON.parse(data);
            if (typeof fileData === 'object' && !Array.isArray(fileData)) {
                return res.json(fileData.moderators || []);
            } else {
                return res.json(fileData);
            }
        } catch (e) {
            console.error("Error parsing moderator file:", e);
            res.status(500).json({ error: 'Server error' });
        }
    });
});

// POST /save-moderators: Saves the provided moderators array while preserving the group name.
app.post('/save-moderators', (req, res) => {
    const { groupId, moderators } = req.body;
    if (!groupId || !Array.isArray(moderators)) {
        return res.status(400).json({ success: false, error: 'Invalid data' });
    }
    const filePath = path.join(groupModsDir, `${groupId}.json`);
    let fileData = { name: "", moderators: moderators }; // default structure
    if (fs.existsSync(filePath)) {
        try {
            const existing = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            if (existing && typeof existing === 'object' && !Array.isArray(existing)) {
                fileData.name = existing.name || "";
            }
        } catch (e) {
            console.error("Error reading existing moderator file:", e);
        }
    }
    fileData.moderators = moderators;
    fs.writeFile(filePath, JSON.stringify(fileData, null, 2), (err) => {
        if (err) {
            console.error("Error saving moderator file:", err);
            return res.status(500).json({ success: false, error: 'Server error' });
        }
        res.json({ success: true });
    });
});

// -----------------------
// Optional: Serve a simple login error page
// -----------------------
app.get('/login', (req, res) => {
    res.send("Error, please contact @lumi_vrc on discord with a description of your previous activity.");
});

// Start the server on port 3000
app.listen(3000, () => {
    console.log("Server running on port 3000");
});
