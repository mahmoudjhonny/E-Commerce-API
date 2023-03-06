const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    firstname: "",
    lastname: "",
    username: { type: String, required: true, unique: true },
    email: { type: String, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    image: { type: String },
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
