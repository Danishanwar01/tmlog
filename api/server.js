const express = require("express");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) throw new Error("BOT_TOKEN missing");

app.post("/auth/telegram/callback", (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).send("initData missing");

  const data = Object.fromEntries(new URLSearchParams(initData));

  const receivedHash = data.hash;
  delete data.hash;

  // ⏳ Expiry check
  const authDate = Number(data.auth_date);
  const now = Math.floor(Date.now() / 1000);
  if (now - authDate > 60) {
    return res.status(403).send("InitData expired");
  }

  const dataCheckString = Object.keys(data)
    .sort()
    .map(k => `${k}=${data[k]}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash !== receivedHash) {
    console.log("HASH FAIL", { dataCheckString });
    return res.status(403).send("Invalid Mini App auth");
  }

  let user;
  try {
    user = JSON.parse(data.user);
  } catch {
    return res.status(400).send("User parse failed");
  }

  res.send(`
    <h2>✅ Login Success</h2>
    <p>${user.first_name} (@${user.username})</p>
    <pre>${JSON.stringify(user, null, 2)}</pre>
  `);
});

module.exports = app;
