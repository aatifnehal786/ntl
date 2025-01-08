const userModel = require('./userModel')
function verifiedEmail(req,res,next)
{

  const userEmail = req.body

  const user = userModel.findOne({email:userEmail})

  if(user.isEmailVerified===false)
  {
    res.status(401).send({message:"Email not verified, Please verify Email"})
    
  }
  else
  {
    next();
    
  }
  
}

module.exports = verifiedEmail;