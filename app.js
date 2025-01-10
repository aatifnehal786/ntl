require("dotenv").config()
const express = require('express')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const userModel = require('./userModel')
const verifiedToken = require('./verifiedToken')
const foodModel = require('./foodModel')
const trackingModel = require('./trackingModel')
const bodyParser = require("body-parser");
const cors = require('cors')
const nodemailer = require('nodemailer')
const crypto = require("crypto");
const port = process.env.PORT || 4000



mongoose.connect(process.env.MONGO_URL)
.then(()=>{
    console.log(`Database connection successful,${process.env.MONGO_URL}`)
})
.catch((err)=>{
    console.log(err)
})

const app = express()

app.use(cors())



const corsOptions = {
    origin: 'https://6781ac258049d09a56efa898--fabulous-fox-1303db.netlify.app', // Replace with your frontend's URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'], // Specify allowed HTTP methods
    allowedHeaders: ['Content-Type', 'Authorization'], // Specify allowed headers
  };
app.options("*", cors(corsOptions));

app.use(cors(corsOptions));
app.use(express.json())

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

const transporter = nodemailer.createTransport({
    service:"gmail",
    
    auth:{
        user:process.env.MY_GMAIL,
        pass:process.env.GMAIL_PASSWORD
    }
})

app.post("/register",(req,res)=>{

    let user = req.body
    bcrypt.genSalt(10,(err,salt)=>{
        if(!err){
            bcrypt.hash(user.password,salt,async (err,hpass)=>{
                user.password=hpass;
                try{
                    let doc = await userModel.create(user)
                    res.status(201).send({doc,message:"User registered"})
                }
                catch(err){
                    console.log(err)
                    res.status(500).send({message:"Some problem"})
                }
            })
        }
    })

})

const otpStorage = {};
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // Generate a 6-digit OTP
  const otp = crypto.randomInt(100000, 999999).toString();

  // Store the OTP (expire in 5 minutes)
  otpStorage[email] = { otp, expiresAt: Date.now() + 2 * 60 * 1000 };

  try {
    // Send the OTP via email
    await transporter.sendMail({
      from: `"Nutrify" <${process.env.MY_GMAIL}>`,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It will expire in 2 minutes.`,
    });

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});

// API to verify OTP
app.post("/verify-otp", async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ error: "Email and OTP are required" });
    }

    const storedData = otpStorage[email];

    if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    try {
        // Mark email as verified
        await userModel.updateOne({ email }, { isEmailVerified: true });

        // Clear the OTP
        delete otpStorage[email];

        res.json({ message: "OTP verified successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Failed to verify OTP" });
    }
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        if (!user.isEmailVerified) {
            return res.status(403).send({ message: "Email not verified. Please verify your email to login." });
        }

        bcrypt.compare(password, user.password, (err, success) => {
            if (err) {
                console.error("Error during password comparison:", err);
                return res.status(500).send({ message: "Error verifying password" });
            }

            if (success) {
                jwt.sign({ email }, process.env.JWT_SECRET_KEY, (err, token) => {
                    if (err) {
                        console.error("Error generating token:", err);
                        return res.status(500).send({ message: "Error generating token" });
                    }

                    return res.status(200).send({
                        token:token,
                        message: "Login successful",
                        userid: user._id,
                        name: user.name,
                    });
                });
            } else {
                return res.status(401).send({ message: "Incorrect password" });
            }
        });
    } catch (error) {
        console.error("Unexpected server error:", error);
        res.status(500).send({ message: "Some problem occurred" });
    }
});



app.get("/foods",verifiedToken,async (req,res)=>{

    let foods = await foodModel.find()
    res.send(foods)

})



app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  // Generate a 6-digit OTP
  const otp = crypto.randomInt(100000, 999999).toString();

  // Store the OTP (expire in 5 minutes)
  otpStorage[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

  try {
    // Send the OTP via email
    await transporter.sendMail({
      from: `"Nutrify" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP code is ${otp}. It will expire in 5 minutes.`,
    });

    res.json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error sending email:", error);
    res.status(500).json({ error: "Failed to send OTP" });
  }
});




app.post("/reset-password", async (req, res) => {
    const { email, newPass, otp } = req.body;

    // Validate input
    if (!email || !otp || !newPass) {
        return res.status(400).json({ error: "Email, OTP, and new password are required" });
    }

    const storedData = otpStorage[email];

    // Verify OTP
    if (!storedData || storedData.otp !== otp || storedData.expiresAt < Date.now()) {
        return res.status(400).json({ error: "Invalid or expired OTP" });
    }

    try {
        // Find user in the database
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Check if the new password matches the current password
        const isSamePassword = await bcrypt.compare(newPass, user.password);
        if (isSamePassword) {
            return res.status(400).json({ error: "New password cannot be the same as the current password" });
        }

        // Hash the new password
        bcrypt.genSalt(10, (err, salt) => {
            if (err) {
                console.error("Error generating salt:", err);
                return res.status(500).send({ message: "Error generating salt" });
            }

            bcrypt.hash(newPass, salt, async (err, hash) => {
                if (err) {
                    console.error("Error hashing password:", err);
                    return res.status(500).send({ message: "Error hashing password" });
                }

                // Update user password
                user.password = hash;
                await user.save();

                // Remove OTP from storage
                delete otpStorage[email];

                res.status(200).send({ message: "Password reset successfully" });
            });
        });
    } catch (error) {
        console.error("Error resetting password:", error);
        res.status(500).send({ message: "Some problem occurred" });
    }
});




app.post("/food/data",verifiedToken,async (req,res)=>{
    let foodItem = req.body
    console.log(foodItem)
    try{

        let newFood = await foodModel.create(foodItem)
        console.log(newFood)
        res.send({newFood,message:"New Food Added"})

    }
    catch(err){
        console.log(err)
        res.send({message:"No data"})

    }
})

app.get("/foods/:name",verifiedToken,async (req,res)=>{
    let foodName = req.params.name
    let searchFood = await foodModel.find({name:{$regex:foodName,$options:'i'}})
    if(searchFood.length!==0){
        res.status(201).send(searchFood)
    }else{
        res.status(404).send({message:"Food Item not Found"})
    }
})

app.post("/track",verifiedToken,async (req,res)=>{

    let trackData = req.body;
    console.log(trackData)
    try{
        let data = await trackingModel.create(trackData)
        console.log(data)
        res.status(201).send({message:"Food added"})
    }
    catch(err){
        console.log(err)
        res.send({message:"No data"})


    }


})

// endpoint to fetch all foods eaten by a single person

app.get("/track/:userid/:date", verifiedToken, async (req, res) => {
    let userid = req.params.userid;
    let date = new Date(req.params.date);
    let strDate = date.getDate() + "/" + (date.getMonth()+1) + "/" + date.getFullYear()
    console.log("Requested date:", strDate);

    try {
        let foods = await trackingModel.find({ user: userid, eatendate: strDate }).populate('user').populate('food');
        console.log("Found foods:", foods); // Log the result
      
        return res.json(foods); // Send data back as JSON if found
    } catch (err) {
        console.error("Error fetching data:", err); // Log any errors
        res.status(500).send({ message: "Some problem occurred" });
    }
});


app.delete("/un-register",verifiedToken,async (req,res)=>{

    const {email} = req.body

   const userEmail = await userModel.findOne({email})



    if(!userEmail)
    {
        return res.status(404).json({message:"User Not Found"})
    }
    
        try
        {
            const user = await userModel.findOneAndDelete({email})
    
            if(user)
            {
                return res.status(200).json({message:"User Un-registered Successfully"})
            }
    
        }
        catch(error)
        {
            console.log(error)
            return res.status(500).json({message:"An error occured while Un-registering User"})
        }
    })






app.listen(port,()=>{
    console.log(`Server is up and running ${port}`)
})
