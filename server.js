const express = require('express');
const cors = require('cors'); // Allows the HTML file to talk to Node
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs'); // Standard encryption library

const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: '50mb' })); // Increase limits for large JSON files
app.use(express.static(path.join(__dirname, 'public')));

// Configuration
const DB_FILE_PATH = './users.json'; 
const APP_PORT = 3000;

// --- DATABASE LOGIC (Simulating a File System) ---

function getUsersFromDB() {
    if (!fs.existsSync(DB_FILE_PATH)) return [];
    
    try {
        const data = fs.readFileSync(DB_FILE_PATH, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        console.error("Error reading users.json:", e.message);
        return [];
    }
}

function saveUsersToDB(users) {
    try {
        fs.writeFileSync(DB_FILE_PATH, JSON.stringify(users));
    } catch (e) {
        console.error("Error saving to file:", e.message);
        throw new Error('Failed to save data.');
    }
}

// --- API ROUTES ---

// 1. REGISTER
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) return res.status(400).json({ error: "Missing fields" });
        
        // Simple check for length (Server side validation)
        if(password.length < 4) return res.status(400).json({ error: "Password too short." });

        const users = getUsersFromDB();
        
        // Check duplicate username
        const existingUser = users.find(u => u.username === username);
        if (existingUser) {
            return res.status(409).json({ error: "Username already exists" });
        }

        // Encrypt password using bcrypt
        // $2a$ is the algorithm, 10 is salt rounds (balance between speed and security)
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = { id: Date.now(), username, password: hashedPassword };

        users.push(newUser);
        saveUsersToDB(users); // Write to the JSON file

        res.status(201).json({ success: true });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    }
});

// 2. LOGIN
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        const users = getUsersFromDB();
        // Find user by username
        const foundUser = users.find(u => u.username === username);

        if (!foundUser) return res.status(401).json({ error: "Invalid credentials" });

        // Compare input password with encrypted hash in DB
        const isMatch = await bcrypt.compare(password, foundUser.password);

        if (isMatch) {
            // Success!
            // In a real app, you would generate a JWT token here. 
            // For this example, we just send back the ID to track them via LocalStorage session.
            return res.status(200).json({ success: true, userId: foundUser.id });
        } else {
            return res.status(401).json({ error: "Invalid password" });
        }

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    }
});

// 3. FORGOT PASSWORD (Change Password)
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { username, newPassword } = req.body;

        if(!username || !newPassword) return res.status(400).json({ error: "Missing fields" });
        
        const users = getUsersFromDB();
        const index = users.findIndex(u => u.username === username);

        if (index === -1) {
            return res.status(404).json({ error: "User not found. Username must exist." });
        }

        // Hash new password and update in the array
        users[index].password = await bcrypt.hash(newPassword, 10);
        
        saveUsersToDB(users);
        
        res.status(200).json({ success: true });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Server Error" });
    }
});

// Start Server
app.listen(APP_PORT, () => {
    console.log(`🚀 Node server running on http://localhost:${APP_PORT}`);
    console.log("📂 Database file will be saved at ./users.json");
    
    // Initialize an empty database if it doesn't exist yet
    if(!fs.existsSync(DB_FILE_PATH)) {
        saveUsersToDB([]);
        console.log("Created empty users.json");
    }
});

