require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const userModel = require("./userModel");
const verifiedToken = require("./verifiedToken");
const foodModel = require("./foodModel");
const trackingModel = require("./trackingModel");
const cors = require("cors");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
// const bodyparser = require('body-parser')
const axios = require('axios')
const app = express();
const port = process.env.PORT || 4000;


const fetch = require("node-fetch")



mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log(`Database connection successful, ${process.env.MONGO_URL}`))
    .catch((err) => console.log(err));

// Middleware
app.use(cors({
  origin: "*", // Allow only your frontend
  credentials: true, // If you're sending cookies or auth headers
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}));

app.use(express.json());
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  next();
});



// Email transporter




// otp storage

const otpStorage = {}

// Register
app.post("/register", async (req, res) => {
  const user = req.body;

  const { reCaptchaValue } = user;

  // ✅ 1. Verify reCAPTCHA with Google
  try {
    const recaptchaResponse = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret: "6LdsmokrAAAAAB1LgyzQtYwgfCVWyC2hhn5MXLBR", // 🔒 Use env in production
        response: reCaptchaValue,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    if (!recaptchaResponse.data.success) {
      return res.status(403).json({ message: "reCAPTCHA verification failed" });
    }
  } catch (err) {
    console.error("reCAPTCHA error:", err.message);
    return res.status(500).json({ message: "Error verifying reCAPTCHA" });
  }

  // ✅ 2. Validate user input
  const olduser = await userModel.findOne({ email: user.email });
  if (olduser)
    return res.status(403).json({ message: "User already registered" });

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(user.email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(user.password)) {
    return res.status(401).json({
      message:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    });
  }

  // ✅ 3. Register user
  try {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);

    const doc = await userModel.create(user);
    res.status(201).json({ doc, message: "User registered" });
  } catch (err) {
    console.error("Registration error:", err.message);
    res.status(500).json({ message: "Server error during registration" });
  }
});


// Login
app.post("/login", async (req, res) => {
  const { email, password, reCaptchaValue, keepSignedIn } = req.body;

  try {
    // 1. Verify reCAPTCHA
    const recaptchaResponse = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret: "6LdsmokrAAAAAB1LgyzQtYwgfCVWyC2hhn5MXLBR",
        response: reCaptchaValue,
      }),
      {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      }
    );

    if (!recaptchaResponse.data.success) {
      return res.status(403).json({ message: "reCAPTCHA failed" });
    }

    // 2. Find user
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // 3. Check email verification
    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Email not verified. Please verify your email." });
    }

    // 4. Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Incorrect password" });

    // 5. Generate tokens
    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // 6. Set cookie BEFORE sending JSON response
    // In login route after generating refreshToken
    user.refreshToken = refreshToken;
    await user.save();

res.cookie("refreshToken", refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  path: "/",
  maxAge: keepSignedIn ? 7 * 24 * 60 * 60 * 1000 : 0
});


    // 7. Send response ONCE
    return res.status(200).json({
      accessToken,
      message: "Login successful",
      userid: user._id,
      name: user.name,
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Refresh Token 
app.post("/refresh-token", async (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token) {
      return res.status(401).json({ message: "Refresh token missing" });
    }

    // Verify signature
    const decoded = jwt.verify(token, REFRESH_SECRET_KEY);

    // Find user
    const user = await userModel.findById(decoded.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // IMPORTANT: compare stored token
    if (user.refreshToken !== token) {
      // Possible stolen/reused token
      user.refreshToken = null;
      await user.save();
      res.clearCookie("refreshToken");
      return res.status(403).json({ message: "Invalid or reused refresh token" });
    }

    // Generate NEW tokens (rotation)
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    // Save new refresh token
    user.refreshToken = newRefreshToken;
    await user.save();

    // Set new cookie
    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
      path: "/",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({ accessToken: newAccessToken });

  } catch (err) {
    console.error("Refresh Error:", err);

    // Expired / invalid refresh token
    res.clearCookie("refreshToken");
    return res.status(403).json({ message: "Invalid or expired refresh token" });
  }
});


// ✅ SEND OTP
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email is required" });

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  // Generate 6-digit OTP
  const otp = Math.floor(100000 + Math.random() * 900000);

  // Store OTP with expiry (10 mins)
  otpStorage[email] = {
    otp: otp.toString(),
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  try {
    const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "Nutrify", email: "nehalahmed05011967@gmail.com" },
        to: [{ email }],
        subject: "Your OTP Code",
        textContent: `Your OTP code is ${otp}. It will expire in 10 minutes.`,
      }),
    });

    const data = await brevoRes.json();
    console.log("Brevo response:", data);

    if (!brevoRes.ok) {
      return res.status(500).json({
        error: "Failed to send OTP email",
        details: data,
      });
    }

    return res.status(201).json({
      message: "OTP sent successfully",
    });
  } catch (error) {
    console.error("Error sending OTP email:", error);
    return res.status(500).json({ error: "Failed to send OTP email" });
  }
});



// ✅ VERIFY OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP are required" });
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  const storedData = otpStorage[email];
  if (
    !storedData ||
    storedData.otp !== otp ||
    storedData.expiresAt < Date.now()
  ) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  try {
    await userModel.updateOne({ email }, { isEmailVerified: true });
    delete otpStorage[email];
    res.json({ message: "OTP verified successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to verify OTP" });
  }
});
function generateAccessToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });
}

function generateRefreshToken(userId) {
  return jwt.sign({ userId }, process.env.REFRESH_SECRET_KEY, { expiresIn: "7d" });
}
// ✅ Forgot Password — Send OTP via Brevo
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  if (!email) return res.status(400).json({ error: "Email is required" });

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  // Generate 6-digit OTP
  const otp = crypto.randomInt(100000, 999999).toString();

  // Store OTP with expiry (5 mins)
  otpStorage[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

  try {
    // Send via Brevo API
    const brevoRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": process.env.BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: { name: "Nutrify", email: "aatifnehal786@gmail.com" },
        to: [{ email }],
        subject: "Your OTP Code - Nutrify",
        textContent: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
      }),
    });

    const data = await brevoRes.json();
    console.log("Brevo response:", data);

    if (!brevoRes.ok) {
      return res.status(500).json({
        error: "Failed to send OTP email",
        details: data,
      });
    }

    return res.status(200).json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("Error sending OTP email:", err);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});


// ✅ Reset Password — Verify OTP and Update Password
app.post("/reset-password", async (req, res) => {
  const { email, newPass, otp } = req.body;

  if (!email || !otp || !newPass)
    return res.status(400).json({ error: "Email, OTP, and new password are required" });

  const storedData = otpStorage[email];
  if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email format" });
  }

  try {
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    // Password strength check
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
    if (!passwordRegex.test(newPass)) {
      return res.status(400).json({
        message:
          "Password must contain at least one uppercase, one lowercase, one number, and one special character",
      });
    }

    const isSame = await bcrypt.compare(newPass, user.password);
    if (isSame)
      return res
        .status(400)
        .json({ error: "New password cannot be the same as the current password" });

    // Hash and save new password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPass, salt);
    await user.save();

    // Delete OTP after successful reset
    delete otpStorage[email];

    res.status(200).json({ message: "Password reset successfully" });
  } catch (err) {
    console.error("Error resetting password:", err);
    res.status(500).json({ message: "Some problem occurred" });
  }
});


// Get All Foods
app.get("/foods", verifiedToken, async (req, res) => {
    const foods = await foodModel.find();
    res.send(foods);
});

// Search Foods
app.get("/foods/:name", verifiedToken, async (req, res) => {
    const foodName = req.params.name;
    console.log(" Searching for food:", foodName);

    try {
        const results = await foodModel.find({ name: { $regex: foodName, $options: "i" } });
        console.log(" Results found:", results);

        if (results.length) {
            res.status(200).json(results);
        } else {
            res.status(404).json({ message: "Food Item not Found" });
        }
    } catch (err) {
        console.error("❌ Error fetching food:", err.message);
        res.status(500).json({ message: "Server Error", error: err.message });
    }
});


// Add Food Item
app.post("/food/data", verifiedToken, async (req, res) => {
    try {
        const newFood = await foodModel.create(req.body);
        res.json({ newFood, message: "New Food Added" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Failed to add food" });
    }
});

// Track Food
app.post("/track", verifiedToken, async (req, res) => {
    try {
        const data = await trackingModel.create(req.body);
        res.status(201).json({ message: "Food added" });
    } catch (err) {
        console.error(err);
        res.status(400).json({ message: "Tracking failed" });
    }
});

// Get Tracked Foods
app.get("/track/:userid/:date", verifiedToken, async (req, res) => {
    const userid = req.params.userid;
    const date = new Date(req.params.date);

    const strDate = (date.getMonth()+1) + "/" + date.getDate() +"/" + date.getFullYear();

    try {
        const foods = await trackingModel.find({
            user: userid,
            eatendate: strDate
        })
        .populate("user")
        .populate("food");

        res.status(200).json(foods);
    } catch (err) {
        console.error("Error fetching data:", err);
        res.status(500).send({ message: "Some problem occurred" });
    }
});


// Delete User
app.delete("/un-register", verifiedToken, async (req, res) => {
    const { email } = req.body;
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ message: "User Not Found" });

    try {
        await userModel.findOneAndDelete({ email });
        res.status(200).json({ message: "User Un-registered Successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "An error occurred while Un-registering User" });
    }
});

// server.js



const OpenAI = require('openai');

const openai = new OpenAI({
  apiKey: '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',
});

app.post('/api/chat', async (req, res) => {
  const { message } = req.body;

  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content: 'You are a helpful AI nutritionist. Give accurate, science-backed and friendly advice.',
        },
        {
          role: 'user',
          content: message,
        },
      ],
    });

    res.json({ reply: response.choices[0].message.content });
  } catch (error) {
    console.error('OpenAI error:', error);
    res.status(500).json({ error: 'Something went wrong with the AI.' });
  }
});




// Start Server
app.listen(port, () => {
    console.log(`Server is up and running on port ${port}`);
});
