const router = require("express").Router();
const { signUpController, logIncontroller } = require("../controllers/auth");

// Register
router.post("/register", signUpController);

// Login
router.post("/login", logIncontroller);

module.exports = router;
