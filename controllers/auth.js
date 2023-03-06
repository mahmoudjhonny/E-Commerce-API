const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// Set Jwt access Token
const accessToken = (id, isAdmin) => {
  return jwt.sign({ id, isAdmin }, process.env.JWT_SECRET_KEY);
};

// Register Controller
const signUpController = async (req, res) => {
  const { firstname, lastname, username, email, password } = req.body;
  try {
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);
    const user = new User({
      firstname,
      lastname,
      username,
      email,
      password: hashedPassword,
    });
    await user.save();
    return res.status(201).json({ massage: "User Created Successfully" });
  } catch (err) {
    res.status(500).json(err);
  }
};

// LogIn Controller
const logIncontroller = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json("User Not Found");
    const isPasswordCorrect = await bcrypt.compare(
      req.body.password,
      user.password
    );
    if (!isPasswordCorrect)
      return res.status(400).json({ result: "Email Or Password InCorrect" });
    const { password, ...other } = user._doc;
    res.status(200).json({
      result: "User LogIn Successfully",
      user: { ...other },
      jwt: accessToken(user._id, user.isAdmin),
    });
  } catch (err) {
    res.status(500).json(err);
  }
};

module.exports = {
  signUpController,
  logIncontroller,
};
