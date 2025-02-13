import express from "express";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import Datastore from "nedb-promises";
import asyncHandler from "express-async-handler";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
dotenv.config();
const User = Datastore.create("Users.db");

const app = express();
app.use(cookieParser());
app.use(express.json());

// Middleware to Authentication user (to be implemented)
const Authentication = (req, res, next) => {
  const accessToken = req.cookies.accessToken;

  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  try {
    // Attempt to verify the access token
    const decodedUser = jwt.verify(accessToken, process.env.SKeyForAT);
    req.user = decodedUser; // Attach user info to request

    return next(); // Token is valid, proceed to the next middleware
  } catch (error) {
    // If token expired, attempt to refresh it
    if (error.name === 'TokenExpiredError') {
      return refreshTokenMiddleware(req, res); // Refresh token and proceed
    }
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};


const Authorization = asyncHandler(async (req, res, next) => {
  const authUser = req.user;
  try {
    if (authUser.Role !== "admin") {
      res.status(401).json({ message: "Unauthorized Account" });
    }
    next();
  } catch {
    return res.status(401).json({ message: "Access token not found" });
  }
});

// Middleware to Authentication user (to be implemented)
const refreshTokenMiddleware = (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh token not found" });
  }

  try {
    // Verify the refresh token
    const decoded = jwt.verify(refreshToken, process.env.SKeyForRT);

    // Generate new tokens
    const { accessToken } = generateToken({
      userId: decoded.userId,
      Role: decoded.Role,
    });

    // Set new tokens in cookies
    setCookies(res, accessToken);
    res.status(200).json({ message: "Access token refreshed" });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired refresh token" });
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

const setCookies = (res, accessToken, refreshToken = null) => {
  // Set accessToken cookie
  res.cookie("accessToken", accessToken, {
    httpOnly: true, // Makes the cookie inaccessible via JavaScript (prevents XSS attacks)
    secure: process.env.NODE_ENV === "production", // Set to true only in production (if using https)
    maxAge: 7 * 60 * 1000, // 7 mins in milliseconds
    sameSite: "Strict", // Prevents sending cookies with cross-site requests (for CSRF protection)
  });

  // If the refreshToken is not provided, you can handle it (for example, logging or sending a specific message).
  if (refreshToken) {
    // Set refreshToken cookie if it exists
    res.cookie("refreshToken", refreshToken, {
      httpOnly: true, // Makes the cookie inaccessible via JavaScript (prevents XSS attacks)
      secure: process.env.NODE_ENV === "production", // Set to true only in production (if using https)
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
      sameSite: "Strict", // Prevents sending cookies with cross-site requests (for CSRF protection)
    });
  } else {
    // Optionally log or handle the case when refreshToken is not provided
    console.log("No refreshToken provided");
    // You could also send a message back, or just not do anything
  }
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

    setCookies(res, accessToken, refreshToken);

    res.status(200).json({
      message: "Login has been done successfully!",
      id: user._id,
      FullName: user.fullName,
      Email: user.email,
      Role: user.role,
    });
  })
);

// get The user Info.
app.get(
  "/api/v1/me",
  Authentication,
  asyncHandler(async (req, res) => {
    const user = await User.findOne({ _id: req.user.userId });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json(user);
  })
);

//is admin
app.get(
  "/api/v1/admin",
  Authentication,
  Authorization,
  asyncHandler((req, res) => {
    const user = req.user;
    if (user) {
      res.status(200).json({ message: `Your Role Is ${user.Role}` });
    } else {
      res
        .status(404)
        .json({ message: `Your Role Is isn't allowed to access this URL` });
    }
  })
);

//create a refreshToken
app.post(
  "/api/v1/refresh-token",
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(400).json({ message: "Refresh token is required" });
    }

    try {
      const decoded = jwt.verify(refreshToken, process.env.SKeyForRT);
      if (!decoded) {
        res.status(401).json({ message: "Invalid refresh token" });
      }
      const { accessToken } = generateToken({
        userId: decoded.userId,
        Role: decoded.Role,
      });
      setCookies(res, accessToken);

      res.status(200).json({ message: "Refresh token is Valid" });
    } catch (err) {
      res.status(401).json({ message: "Invalid refresh token" });
    }
  })
);

//logout
app.post("/api/v1/logout", (req, res) => {
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.json({ message: "Logged out successfully" });
});
//---------------------------------------------------------------//

//---------------------------------------------------------------//

// Server Setup
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
