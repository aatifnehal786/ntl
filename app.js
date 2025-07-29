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



mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log(`Database connection successful, ${process.env.MONGO_URL}`))
    .catch((err) => console.log(err));

// Middleware
app.use(cors({
  origin: "https://nutrify247.netlify.app", // Allow only your frontend
  credentials: true, // If you're sending cookies or auth headers
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}));
// app.options("*", cors(corsOptions));
app.use(express.json());
// app.use((req, res, next) => {
//     res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
//     res.setHeader("Pragma", "no-cache");
//     res.setHeader("Expires", "0");
//     next();
// });


// Email transporter
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.MY_GMAIL,
        pass: process.env.GMAIL_PASSWORD
    }
});

const otpStorage = {};

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


// Send OTP
app.post("/send-otp", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const otp = crypto.randomInt(100000, 999999).toString();
    otpStorage[email] = { otp, expiresAt: Date.now() + 2 * 60 * 1000 };

    try {
        await transporter.sendMail({
            from: `"Nutrify" <${process.env.MY_GMAIL}>`,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}. It will expire in 2 minutes.`,
        });
        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        console.error("Error sending email:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

// Verify OTP
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;
    const storedData = otpStorage[email];

    if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
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
// Login
app.post("/login", async (req, res) => {
  const { email, password, reCaptchaValue, keepSignedIn } = req.body;

  try {
    // ✅ 1. Verify reCAPTCHA
    const recaptchaResponse = await axios.post(
      "https://www.google.com/recaptcha/api/siteverify",
      new URLSearchParams({
        secret: "6LdsmokrAAAAAB1LgyzQtYwgfCVWyC2hhn5MXLBR",
        response: reCaptchaValue,
      }),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    if (!recaptchaResponse.data.success) {
      return res.status(403).json({ message: "reCAPTCHA failed" });
    }

    // ✅ 2. Find user
    const user = await userModel.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    // ✅ 3. Check if email verified
    if (!user.isEmailVerified) {
      return res
        .status(403)
        .json({ message: "Email not verified. Please verify your email to login." });
    }

    // ✅ 4. Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Incorrect password" });

    // ✅ 5. Generate JWT
    const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id);

    res.status(200).json({
      accessToken,
      message: "Login successful",
      userid: user._id,
      name: user.name,
    });

      res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "Strict",
    maxAge: keepSignedIn ? 7 * 24 * 60 * 60 * 1000 : 0 // 7 days or session-only
  });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post("/refresh-token", (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return res.status(401).json({ msg: "No token" });

  jwt.verify(token, REFRESH_SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ msg: "Invalid token" });

    const accessToken = generateAccessToken(decoded.userId);
    res.json({ accessToken });
  });
});



// Forgot Password
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "Email is required" });

    const otp = crypto.randomInt(100000, 999999).toString();
    otpStorage[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    try {
        await transporter.sendMail({
            from: `"Nutrify" <${process.env.MY_GMAIL}>`,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
        });
        res.json({ message: "OTP sent successfully" });
    } catch (err) {
        console.error("Error sending email:", err);
        res.status(500).json({ error: "Failed to send OTP" });
    }
});

// Reset Password
app.post("/reset-password", async (req, res) => {
    const { email, newPass, otp } = req.body;
    const storedData = otpStorage[email];

    if (!email || !otp || !newPass) return res.status(400).json({ error: "Email, OTP, and new password are required" });
    if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
    }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
              if (!emailRegex.test({email})) {
                return res.status(400).json({ message: "Invalid email format" });
              }

    try {
        const user = await userModel.findOne({ email });

            
        if (!user) return res.status(404).json({ error: "User not found" });

  

  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test({newPass})) {
    return res.status(401).json({
      message:
        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character",
    });
  }

        const isSame = await bcrypt.compare(newPass, user.password);
        if (isSame) return res.status(400).json({ error: "New password cannot be the same as the current password" });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPass, salt);
        await user.save();
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
