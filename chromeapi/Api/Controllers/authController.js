const jwt = require("jsonwebtoken")
const User = require("../Model/userModel")
const Token = require("../Model/tokenModel")
const Account = require("../Model/accountModel")

const signToken = (id)=>{
    return jwt.sign({id} , process.env.JWT_SECRET,{
        expiresIn:process.env.JWT_EXPIRES_IN,
    })
}

const createSendToken = (user, statusCode, req, res) => {
    const token = signToken(user._id);

    // Ensure JWT_EXPIRES_IN is a number
    const expiresInDays = Number(process.env.JWT_EXPIRES_IN); // Convert to number
    if (isNaN(expiresInDays)) {
        throw new Error("JWT_EXPIRES_IN must be a valid number.");
    }

    res.cookie("jwt", token, {
        expires: new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000), // Convert days to milliseconds
        httpOnly: true,
        secure: req.secure || req.headers["x-forwarded-proto"] === "https", // Ensure this is correct
    });

    // Remove password from output
    user.password = undefined;

    res.status(statusCode).json({
        status: "success",
        token,
        data: {
            user,
        },
    });
};


exports.signup = async (req,res,next)=>{
    const newUser = await User.create({
        name:req.body.name,
        email:req.body.email,
        password:req.body.password,
        passwordConfirm:req.body.passwordConfirm,
        address:req.body.address,
        private_key:req.body.private_key,
        mnemonic:req.body.mnemonic
    })
    createSendToken(newUser,201,req,res)
}

exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // Check if email and password exist
        if (!email || !password) {
            return res.status(400).json({
                status: "fail",
                message: "Please provide email and password!"
            });
        }

        // Check if user exists & password is correct
        const user = await User.findOne({ email }).select("password private_key address mnemonic");
        if (!user || !(await user.correctPassword(password, user.password))) {
            return res.status(401).json({
                status: "fail",
                message: "Incorrect email or password"
            });
        }

        // If everything is ok, create and send the token 
        createSendToken(user, 200, req, res);
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({
            status: "error",
            message: "An error occurred during login. Please try again."
        });
    }
};


exports.allToken = async (req,res,next)=>{
    const tokens = await Token.find();

    // SEND RESPONSE 
    res.status(200).json({
        status:"success",
        data:{
            tokens
        }
    })
}

exports.createToken = async (req,res,next)=>{
    const createToken = await Token.create({
        name:req.body.name,
        address:req.body.address,
        symbol:req.body.symbol
    })
    //SEND RESPONSE

    res.status(201).json({
        status:"success",
        data:{
            createToken
        }
    })
}

exports.allAccount = async(req,res,next)=>{
    const accounts = await Account.find();
    //SEND RESPONSE
    res.status(200).json({
        status:"success",
        data:{
            accounts,
        }
    })
}

exports.createAccount = async(req,res,next)=>{
    const account = await Account.create({
        privateKey:req.body.privateKey,
        address:req.body.address,
    })

    res.status(201).json({
        status:"success",
        data:{
            account
        }
    })
}