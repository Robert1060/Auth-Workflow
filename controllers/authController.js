const User = require('../models/User');
const Token = require('../models/Token')
const { StatusCodes } = require('http-status-codes');
const CustomError = require('../errors');
const { attachCookiesToResponse, createTokenUser,sendVerificationEmail, sendResetPasswordEmail, createHash } = require('../utils');

const crypto = require('crypto');

const register = async (req, res) => {
  const { email, name, password } = req.body;

  const emailAlreadyExists = await User.findOne({ email });
  if (emailAlreadyExists) {
    throw new CustomError.BadRequestError('Email already exists');
  }

  // first registered user is an admin
  const isFirstAccount = (await User.countDocuments({})) === 0;
  const role = isFirstAccount ? 'admin' : 'user';


  const verificationToken = crypto.randomBytes(40).toString('hex')

  const origin = 'https://auth-workflow-11.herokuapp.com'

  //  const tempOrigin = req.get('origin')
  //  const protocol = req.protocol
  //  const host = req.get('host')    // iin raw headers maybe :(
  //  const forwardedHost = req.get('x-forwarded-host')
  //  const forwardedProtocol = req.get('x-forwarded-proto')


  // LOGS MIGHT NEED LATER
  //  console.log(`origin: ${tempOrigin}`);
  //  console.log(`protocol: ${protocol}`);
  //  console.log(`host : ${host}`);
  //  console.log(`forwarded-host : ${forwardedHost}`);
  //  console.log(`Forwarded-protocol : ${forwardedProtocol}`);

  const user = await User.create({ name, email, password, role , verificationToken});

  await sendVerificationEmail({
    name:user.name,
    email:user.email,
    verificationToken:user.verificationToken,
    origin,})

  // send verificationToken only while resting in postman
  res.status(StatusCodes.CREATED).json({ msg:'Success !! Please verify your email'})
 
};
const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    throw new CustomError.BadRequestError('Please provide email and password');
  }
  const user = await User.findOne({ email });

  if (!user) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }
  const isPasswordCorrect = await user.comparePassword(password);
  if (!isPasswordCorrect) {
    throw new CustomError.UnauthenticatedError('Invalid Credentials');
  }

  const isUserVerified = user.isVerified
  if(!isUserVerified){
    throw new CustomError.UnauthenticatedError('Please verify your email')
  }

  const tokenUser = createTokenUser(user);

  // create refresh token
  let refreshToken = '';
  // check for existing token
  const existingToken = await Token.findOne({user:user._id})
  if(existingToken){
    const {isValid} = existingToken
    if(!isValid){
      throw new CustomError.UnauthenticatedError('Invalid credentials')
    }
    refreshToken = existingToken.refreshToken
    attachCookiesToResponse({res,user:tokenUser,refreshToken})
    res.status(StatusCodes.OK).json({ user: tokenUser })
    return;
  }


  refreshToken = crypto.randomBytes(40).toString('hex')
  const userAgent = req.headers['user-agent']
  const ip = req.ip
  const userToken = {refreshToken,userAgent,ip,user:user._id}

  Token.create(userToken)

  attachCookiesToResponse({ res, user: tokenUser, refreshToken });

  res.status(StatusCodes.OK).json({ user: tokenUser });
};
const logout = async (req, res) => {

  await Token.findOneAndDelete({user:req.user.userId})
  
  res.cookie('accessToken', 'logout', {
    httpOnly: true,
    expires: new Date(Date.now())
  });
  res.cookie('refreshToken','logout',{
    httpOnly:true,
    expires: new Date(Date.now())
  })
  res.status(StatusCodes.OK).json({msg:'User logged out succesfully !!!'})
  //res.redirect('localhost:3000/api/v2')
  //return res.end()
};

const verifyEmail = async (req,res) => {
  const {verificationToken, email} = req.body

  if(!verificationToken || !email){
    throw new CustomError.BadRequestError('Please provide verification token and email')
  }

  const user = await User.findOne({email})
  if(!user){
    throw new CustomError.UnauthenticatedError('Verification failed')
  }
  const userToken = user.verificationToken
  if(verificationToken !== userToken){
   throw new CustomError.UnauthenticatedError('Wrong verification token')
  }
  user.isVerified = true,
  user.verified = Date.now()
  user.verificationToken = ''


  await user.save()
  res.status(StatusCodes.OK).json({msg:'Email verified succesfully'})
}

const forgotPassword = async (req,res) => {
  const {email} = req.body
  if(!email){
    throw new CustomError.BadRequestError('Please provide valid email')
  }
  const user = await User.findOne({email})
  if(user){
    const passwordToken = crypto.randomBytes(70).toString('hex');
    // send email
    const origin = 'https://auth-workflow-11.herokuapp.com'

    await sendResetPasswordEmail({name:user.name,email:user.email,token:passwordToken,origin})
    
    const tenMinutes = 1000 * 60 * 10
    const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)

    user.passwordToken = createHash(passwordToken),
    user.passwordTokenExpirationDate = passwordTokenExpirationDate
    await user.save()
  }
 
 res.status(StatusCodes.OK).json({msg:'Please check your email for reset password link'})
}


const resetPassword = async (req,res) => {
  const {token,email,password} = req.body
  if(!token || !email || !password){
    throw new CustomError.BadRequestError('Please provide all the credentials')
  }
 const user = await User.findOne({email})
 if(user){
    const currentDate = new Date()
    if(user.passwordToken === createHash(token) && user.passwordTokenExpirationDate > currentDate){
        user.password = password
        user.passwordToken = null
        user.passwordTokenExpirationDate = null
        await user.save()
    }
 }
 res.send('reset password')
}

module.exports = {
  register,
  login,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
};
