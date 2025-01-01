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
app.use(express.json())
app.use(cors())


app.use(cors({
  origin: "http://localhost:5173", // Replace with your frontend's origin
  methods: "GET, POST, PUT, DELETE",
  credentials: true,
}));


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

// API to verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP are required" });
  }

  const storedData = otpStorage[email];

  // Check if OTP exists and is valid
  if (
    !storedData ||
    storedData.otp !== otp ||
    storedData.expiresAt < Date.now()
  ) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  // OTP is valid, delete it from storage
  delete otpStorage[email];

  res.json({ message: "OTP verified successfully" });
});

app.post("/login",async (req,res)=>{
    let userCred = req.body
    try{
        let user = await userModel.findOne({email:userCred.email})
        console.log(user)
    if(user!==null){
        bcrypt.compare(userCred.password,user.password,(err,success)=>{
            if(success==true){
                jwt.sign({email:userCred.email},process.env.JWT_SECRET_KEY,(err,token)=>{
                    if(!err){
                        res.status(201).send({token:token,message:"Login success",userid:user._id,name:user.name})
                    }
                    else{
                        res.status(403).send({message:"Some problem while generating token"})
                    }
                })
                
            }else{
                res.status(401).send({message:"Wrong password"})
            }
        })
    }else{
        res.status(404).send({message:"User not found please login again"})
    }

    }catch(err){
        console.log(err)
        res.status(500).send({message:"Some Problem"})

    }
})



app.get("/foods",verifiedToken,async (req,res)=>{

    let foods = await foodModel.find()
    res.send(foods)

})



app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    try {
        if (!email) {
            return res.status(400).send({ message: "Please provide email" });
        }

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }

        // Generate token
        const token = jwt.sign({ email }, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });

        // Save token and expiration in the user's record
        user.resetToken = {
            token,
            expires: new Date(Date.now() + 3600000), // 1 hour from now
        };
        await user.save();

        // Send email with reset link
        const resetLink = `${process.env.RESET_LINK}/${token}`;
        const receiver = {
            from: process.env.MY_GMAIL,
            to: email,
            subject: "Password Reset Link",
            text: `Click on this link to reset your password: ${resetLink}`,
        };

        transporter.sendMail(receiver, (err, info) => {
            if (err) {
                return res.status(500).send({ message: "Error sending email" });
            } else {
                return res.status(200).send({ message: "Password reset link sent to your email" });
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Some problem occurred" });
    }
});




app.post("/reset-password/:token", async (req, res) => {
    const { token } = req.params;
    const { newPass } = req.body;

    try {
        // Verify the token
        const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const email = decoded.email;

        // Find the user with the reset token
        const user = await userModel.findOne({ email, "resetToken.token": token });
        if (!user || user.resetToken.expires < new Date()) {
            return res.status(400).send({ message: "Invalid or expired token" });
        }

        // Hash the new password
        bcrypt.genSalt(10, (err, salt) => {
            if (err) return res.status(500).send({ message: "Error generating salt" });

            bcrypt.hash(newPass, salt, async (err, hash) => {
                if (err) return res.status(500).send({ message: "Error hashing password" });

                // Update password and clear reset token
                user.password = hash;
                user.resetToken = undefined;
                await user.save();

                res.status(200).send({ message: "Password reset successfully" });
            });
        });
    } catch (error) {
        console.error(error);
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
    let strDate = date.getDate() + "/" + (date.getMonth() + 1) + "/" + date.getFullYear();
    console.log("Requested date:", strDate);

    try {
        let foods = await trackingModel.find({ user: userid, eatendate: strDate }).populate('user').populate('food');
        console.log("Found foods:", foods); // Log the result
        if (foods.length === 0) {
            return res.status(204).send(); // No data found, return 204
        }
        return res.json(foods); // Send data back as JSON if found
    } catch (err) {
        console.error("Error fetching data:", err); // Log any errors
        res.status(500).send({ message: "Some problem occurred" });
    }
});







const path = require("path");

// Serve React static files
app.use(express.static("./"));

// Fallback route to handle frontend paths
app.get("*", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"), (err) => {
        if (err) {
            console.error('Error sending index.html:', err);
            res.status(500).send('Internal Server Error');
        }
    });
});

app.listen(port,()=>{
    console.log(`Server is up and running ${port}`)
})
