const express = require("express");
const crypto = require("crypto");
const cors = require("cors");

const app = express();

app.use(express.json());

app.use(cors({
  origin: "https://tmlog.vercel.app", 
  methods: ["POST", "GET", "OPTIONS"],
  credentials: true
}));

const BOT_TOKEN = process.env.BOT_TOKEN;

function parseInitData(initData) {
  return Object.fromEntries(
    initData.split("&").map(part => {
      const [key, value] = part.split("=");
      return [key, decodeURIComponent(value)]; // ✅ decode before verification
    })
  );
}

app.post("/auth/telegram/callback", (req, res) => {
  const { initData } = req.body;
  if (!initData) return res.status(400).send("❌ initData missing");

  const data = parseInitData(initData);
  const receivedHash = data.hash;
  delete data.hash;

  const dataCheckString = Object.keys(data)
    .sort()
    .map(k => `${k}=${data[k]}`)
    .join("\n");

  const secretKey = crypto.createHash("sha256").update(BOT_TOKEN).digest();
  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash !== receivedHash) {
    console.log("HASH MISMATCH", { receivedHash, calculatedHash });
    return res.status(403).send("❌ Invalid Mini App auth");
  }

  const user = JSON.parse(data.user);

  res.send(`<h2>✅ Welcome ${user.first_name}</h2>`);
});

module.exports = app;
