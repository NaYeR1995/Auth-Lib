import express from "express";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import Datastore from "nedb-promises";
import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";

dotenv.config();
const User = Datastore.create("Users.db");

const app = express();
app.use(express.json());

// Middleware to authenticate user (to be implemented)
const authen = (req, res, next) => {
  const authorizationHeader = req.headers.authorization;

  if (!authorizationHeader) {
    return res.status(401).json({ message: "Access token not found" });
  }
  const token = authorizationHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token is missing" });
  }

  try {
    const decoded = jwt.verify(token, process.env.SKeyForAT);
    req.user = { id: decoded.userId, Role:decoded.role };
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

const generateToken = (data) => {
  const accessToken = jwt.sign(data, process.env.SKeyForAT, {
    expiresIn: process.env.ExpireAT,
  });

  const refreshToken = jwt.sign(data, process.env.SKeyForRT, {
    expiresIn: process.env.ExpireRT,
  });
  return { accessToken, refreshToken };
};

// Default Route
app.get("/", (req, res) => {
  res.status(200).json({ Message: "Welcome to My API App" });
});

// Register
app.post(
  "/api/v1/register",
  asyncHandler(async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
      return res.status(400).json({ message: "Data Not Found." });
    }

    const emailLower = email.toLowerCase();

    const user = await User.findOne({ email: emailLower });
    if (user) {
      return res.status(409).json({ message: "Email already exists" });
    }

    try {
      const salt = await bcrypt.genSalt(12);
      const hashPassword = await bcrypt.hash(password, salt);

      const newUser = await User.insert({
        fullName,
        email: emailLower,
        password: hashPassword,
        role: "user",
        active: true,
        isBan: false,
      });

      return res.status(201).json({
        message: "User created successfully",
        id: newUser._id,
        FullName: newUser.fullName,
        Email: newUser.email,
        Role: newUser.role,
      });
    } catch (err) {
      res.status(500).json({ message: err });
    }
  })
);

// Login
app.post(
  "/api/v1/login",
  asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required!" });
    }

    const emailLower = email.toLowerCase();
    const user = await User.findOne({ email: emailLower });

    if (!user) {
      return res.status(404).json({ message: "user or password Is Invalid" });
    }

    if (user.isBan || !user.active) {
      return res
        .status(403)
        .json({ message: "Your account is banned or inactive." });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "user or password Is Invalid!" });
    }

    const { accessToken, refreshToken } = generateToken({
      userId: user._id,
      Role: user.role,
    });

    res.status(200).json({
      message: "Login has been done successfully!",
      id: user._id,
      FullName: user.fullName,
      Email: user.email,
      Role: user.role
    });
    console.log(accessToken)
    console.log(refreshToken)
  })
);

// CRUD Auth checking
app.get(
  "/api/v1/me",
  authen,
  asyncHandler(async (req, res) => {
    const user = await User.findOne({ _id: req.user.id });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  })
);

app.post("/api/v1/refresh-token", asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: "Refresh token is required" });
  }

  try {
    const decoded = jwt.verify(refreshToken, process.env.SKeyForRT);
    const { accessToken, refreshToken: newRefreshToken } = generateToken({
      userId: decoded.userId,
      Role: decoded.Role,
    });

    res.status(200).json({ accessToken, refreshToken: newRefreshToken });
  } catch (err) {
    res.status(401).json({ message: "Invalid refresh token" });
  }
}));

// Server Setup
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
