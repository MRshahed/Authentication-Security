require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const ejs = require("ejs");
const bodyparser = require("body-parser");
const encryption = require("mongoose-encryption");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.secret,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/secretDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const user = mongoose.model("user", userSchema);

passport.use(user.createStrategy());
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture
    });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.client_id,
    clientSecret:  process.env.client_secret,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    user.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req, res) => {
  res.render("home");
});

app.get('/auth/google', passport.authenticate("google", { 
    scope: ['profile'] 
}));
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.get("/secrets", (req, res) => {
 user.find({"secret":{$ne:null}},(err, found)=>{
  if(found){
    res.render("secrets", {usersecrets: found});
  }
 })
});

app.route("/submit")
.get((req,res)=>{
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})
.post((req,res)=>{
   const post = req.body.secret;

   user.findById(req.user.id, (err, founduser)=>{
    if(founduser){
      founduser.secret = post;
      founduser.save(()=>{
        res.redirect("/secrets");
      })
    }
   })
});

// Login route

app.route("/login")

  .get((req, res) => {
    res.render("login");
  })

  .post((req, res) => {
    const email = req.body.username;
    const pass = req.body.password;

    const newuser = new user({
      username: email,
      password: pass,
    });
    req.login(newuser, (err) => {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
  });

// Register route

app.route("/register")

  .get((req, res) => {
    res.render("register");
  })

  .post((req, res) => {
    user.register(
      { username: req.body.username },
      req.body.password,
      (err, user) => {
        if (err) {
          console.log(err);
          res.redirect("/register");
        } else {
          passport.authenticate("local")(req, res, () => {
            res.redirect("/secrets");
          });
        }
      }
    );
  });

app.get("/logout", (req, res) => {
  req.logout((err) => {});
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("Server is running on Port 3000");
});
