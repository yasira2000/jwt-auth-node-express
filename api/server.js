require("dotenv").config();
const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 5000;

app.use(express.json());
const cors = require("cors");
app.use(cors());

// This array is only for demostration purpose
// Actual user data should be stored in a database
const users = [
  {
    id: "1",
    username: "john",
    password: "john123",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "jane123",
    isAdmin: false,
  },
];

// This array is only for demostration purpose.
// In real world you have to store these refresh tokens in a database
let refreshTokens = [];

const generateAccessToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "20s" }
  );
};
const generateRefreshToken = (user) => {
  return jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    process.env.REFRESH_TOKEN_SECRET
  );
};

app.post("/api/refresh", (req, res) => {
  // take the refresh token from the user
  const refreshToken = req.body.refreshToken;

  // Send error if there is no token or the token is invalid
  if (!refreshToken)
    return res.status(401).json({
      success: false,
      message: "You are not authenticated!",
    });

  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json({
      success: false,
      message: "Refresh token is not valid",
    });
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      res.status(403).json({
        success: false,
        message: "Refresh token is not valid",
      });
    }

    // Remove the current refresh token from the list and keep others refresh tokens
    refreshTokens = refreshTokens.filter((token) => {
      token !== refreshToken;
    });

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateRefreshToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      success: true,
      message: "New access token created.",
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      },
    });
  });

  // If everything ok then create new access token and refresh token and send to the user
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  // check if the username and password match
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    // if username and password are matched then create a access token
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);

    res.status(200).json({
      success: true,
      message: "Login successful",
      data: {
        username: user.username,
        isAdmin: user.isAdmin,
        accessToken,
        refreshToken,
      },
    });
  } else {
    res.status(400).json({
      success: false,
      message: "Username or password incorrect",
    });
  }
});

// This is the middleware that we are going to use to identify,
// if the user is authenticated before every user activity
const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const accessToken = authHeader.split(" ")[1];

    jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
      // Even the Authorization header is there the token is invalid. (may be expired)
      if (err) {
        return res.status(403).json({
          success: false,
          message: "Token is not valid",
        });
      }
      // Token is valid
      req.user = user;
      next();
    });
  }
  // Autorization header is not there
  else {
    res.status(401).json({
      success: false,
      message: "You are not authenticated!",
    });
  }
};

// Regular user can only delete his own account
// But Admin user can delete any account
app.delete("/api/users/:userId", verify, (req, res) => {
  // check if the user trying to delete his own account or the user is an admin
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json({
      success: true,
      message: "User has been deleted.",
    });
  } else {
    res.status(403).json({
      success: false,
      message: "You are not authorized to delete this user!",
    });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
