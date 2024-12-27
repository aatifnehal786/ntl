const jwt = require('jsonwebtoken')
require("dotenv").config()
const verifiedToken = (req, res, next) => {
    let token = req.headers.authorization.split(" ")[1]
    try {
        let token = req.headers.authorization.split(" ")[1]
        jwt.verify(token,process.env.JWT_SECRET_KEY,(err,result)=>{
            if(!err){
                next()
            }
        })
    }
    catch (err) {
        console.log(err)
        res.send({ message: "Some problem" })
    }
}

module.exports = verifiedToken;