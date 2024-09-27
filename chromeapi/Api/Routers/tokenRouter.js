const express = require("express")

const authController = require("../Controllers/authController")

const router = express.Router()


router.get("/alltokens",authController.allToken)

router.post("/createtoken",authController.createToken)

module.exports = router