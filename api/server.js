// server.js
const express = require("express");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

// ✅ Allow requests from your Mini App frontend
app.use(cors({
  origin: "https://tmlogabcd.vercel.app", // Replace with your frontend URL
  methods: ["POST", "GET", "OPTIONS"],
  credentials: true
}));

app.use(express.json());

// Telegram Bot Token from environment
const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
  throw new Error("❌ BOT_TOKEN missing in environment variables!");
}

// Parse initData safely using URLSearchParams
function parseInitData(initData) {
  return Object.fromEntries(new URLSearchParams(initData));
}

// Telegram Mini App callback
app.post("/auth/telegram/callback", (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).send("❌ initData missing");

  const data = parseInitData(initData);

  const receivedHash = data.hash;
  delete data.hash;

  // Create data check string (sorted)
  const dataCheckString = Object.keys(data)
    .sort()
    .map(key => `${key}=${data[key]}`)
    .join("\n");

  // Telegram recommends using HMAC with BOT_TOKEN directly
  const secretKey = crypto.createHmac("sha256", BOT_TOKEN).digest();
  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash !== receivedHash) {
    console.log("HASH MISMATCH", { receivedHash, calculatedHash, dataCheckString });
    return res.status(403).send("❌ Invalid Mini App auth");
  }

  // ✅ Only parse user after verification
  const user = JSON.parse(data.user);

  res.send(`
    <h2>✅ Welcome ${user.first_name}</h2>
    <pre>${JSON.stringify(user, null, 2)}</pre>
  `);
});

module.exports = app;

// Optional: Start server locally
if (require.main === module) {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}
