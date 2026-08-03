const fs = require("fs");
const express = require("express");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// ======================
// Middleware
// ======================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));

// ======================
// Rate Limiter
// ======================
const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: `
        <h2>🚫 Too Many Requests</h2>
        <p>Please try again after one minute.</p>
    `
});

app.use(limiter);

// ======================
// Create logs folder
// ======================
if (!fs.existsSync("logs")) {
    fs.mkdirSync("logs");
}

// ======================
// Attack Logger
// ======================
function logAttack(type, username) {

    const log =
`[${new Date().toISOString()}] ${type} attack detected | Username: ${username}\n`;

    fs.appendFile("logs/waf.log", log, err => {
        if (err) console.log(err);
    });

}
// ======================
// Home Page
// ======================
app.get("/", (req, res) => {

    res.send(`
        <h1>Traffic Filtering & Rate Limiting WAF</h1>

        <p><a href="/login">Login Page</a></p>

        <p><a href="/logs">View WAF Dashboard</a></p>
    `);

});

// ======================
// Login Page
// ======================
app.get("/login", (req, res) => {

    res.send(`

<!DOCTYPE html>

<html>

<head>

<title>Demo Login</title>

</head>

<body style="font-family:Arial;margin:60px;">

<h2>Demo Login</h2>

<form method="POST" action="/login">

<input
type="text"
name="username"
placeholder="Username"
required>

<br><br>

<input
type="password"
name="password"
placeholder="Password"
required>

<br><br>

<button type="submit">
Login
</button>

</form>

</body>

</html>

`);

});
// ======================
// Login Handler
// ======================
app.post("/login", (req, res) => {

const { username, password } = req.body;

const sqlPattern =
/('|--|DROP|SELECT|INSERT|DELETE|UPDATE|UNION|OR\s+1=1)/i;

const xssPattern =
/<script>|<\/script>|javascript:|alert\(|onerror=|onload=/i;

const commandPattern =
/(&&|\|\||whoami|pwd|ls|cat|curl|wget|rm)/i;

const lfiPattern =
/(\.\.\/|\/etc\/passwd|boot\.ini|windows\\system32)/i;

// SQL
if(sqlPattern.test(username)||sqlPattern.test(password)){

logAttack("SQL Injection",username);

return res.status(403).send(`
<h2>🚫 Request Blocked</h2>
<p><b>Attack Type:</b> SQL Injection</p>
`);

}

// XSS
if(xssPattern.test(username)||xssPattern.test(password)){

logAttack("XSS",username);

return res.status(403).send(`
<h2>🚫 Request Blocked</h2>
<p><b>Attack Type:</b> Cross Site Scripting (XSS)</p>
`);

}

// Command Injection
if(commandPattern.test(username)||commandPattern.test(password)){

logAttack("Command Injection",username);

return res.status(403).send(`
<h2>🚫 Request Blocked</h2>
<p><b>Attack Type:</b> Command Injection</p>
`);

}

// Directory Traversal
if(lfiPattern.test(username)||lfiPattern.test(password)){

logAttack("Directory Traversal",username);

return res.status(403).send(`
<h2>🚫 Request Blocked</h2>
<p><b>Attack Type:</b> Directory Traversal / LFI</p>
`);

}

// Success
res.send(`
<h2>✅ Login Successful</h2>

<p><b>Username:</b> ${username}</p>

<p><b>Password:</b> ${password}</p>

<p><a href="/logs">View Dashboard</a></p>
`);

});
// ======================
// WAF Dashboard
// ======================
app.get("/logs", (req, res) => {

    fs.readFile("logs/waf.log", "utf8", (err, data) => {

        if (err) {
            return res.send("<h2>No attack logs found.</h2>");
        }

        const logs = data.split("\n").filter(line => line.trim() !== "");

        let sql = 0;
        let xss = 0; 
        let cmd = 0;
        let lfi = 0;

        let rows = "";

        logs.forEach(log => {

            let attack = "Unknown";

            if (log.includes("SQL Injection")) {
                attack = "🔴 SQL Injection";
                sql++;
            }
           else if (
    log.includes("Cross-Site Scripting") ||
    log.includes("XSS")
) {
    attack = "🟠 Cross-Site Scripting (XSS)";
    xss++;
}
            else if (log.includes("Command Injection")) {
                attack = "🟣 Command Injection";
                cmd++;
            }
            else if (log.includes("Directory Traversal")) {
                attack = "🔵 Directory Traversal / LFI";
                lfi++;
            }

            rows += `
                <tr>
                    <td>${attack}</td>
                    <td>${log}</td>
                </tr>
            `;

        });

        res.send(`

<!DOCTYPE html>

<html>

<head>

<title>WAF Dashboard</title>

<style>

body{
    background:#101820;
    color:white;
    font-family:Arial;
    margin:40px;
}

h1{
    color:#00ff99;
    text-align:center;
}

.cards{
    display:flex;
    justify-content:center;
    gap:20px;
    flex-wrap:wrap;
    margin-bottom:30px;
}

.card{
    background:#1d1d1d;
    padding:20px;
    border-radius:10px;
    width:170px;
    text-align:center;
    box-shadow:0 0 10px rgba(0,255,153,.3);
}

.card h2{
    margin:10px 0;
    color:#00ff99;
}

table{
    width:100%;
    border-collapse:collapse;
}

th{
    background:#00b894;
    color:white;
    padding:12px;
}

td{
    border:1px solid #444;
    padding:10px;
}

tr:nth-child(even){
    background:#1a1a1a;
}

tr:hover{
    background:#2d2d2d;
}

a{
    color:#00ff99;
    text-decoration:none;
}

</style>

</head>

<body>

<h1>🛡 Web Application Firewall Dashboard</h1>

<div class="cards">

<div class="card">
<h3>Total Attacks</h3>
<h2>${logs.length}</h2>
</div>

<div class="card">
<h3>SQL Injection</h3>
<h2>${sql}</h2>
</div>

<div class="card">
<h3>XSS</h3>
<h2>${xss}</h2>
</div>

<div class="card">
<h3>Command Injection</h3>
<h2>${cmd}</h2>
</div>

<div class="card">
<h3>Directory Traversal</h3>
<h2>${lfi}</h2>
</div>

</div>

<table>

<tr>
<th>Attack Type</th>
<th>Log Entry</th>
</tr>

${rows}

</table>

<br><br>

<a href="/">🏠 Home</a> |
<a href="/login">🔐 Login</a>

</body>

</html>

`);

    });

});

// ======================
// Start Server
// ======================
app.listen(PORT, () => {

    console.log(`🚀 Server running on http://localhost:${PORT}`);

});