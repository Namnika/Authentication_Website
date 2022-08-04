//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

// SET UP SESSION------below code comes from express-session
app.use(session({
  secret: "This is little secret.",
  resave: false,
  saveUninitialized: true
}));

// ----MANAGE SESSIONS
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb+srv://admin-namnika:test123cluster0.9ptqm53.mongodb.net/userDB"});


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  githubId: String,
  secret: String
});

// CREATE PLUGIN MONGOOSE SCHEMA
userSchema.plugin(passportLocalMongoose, {usernameField: "username"});
userSchema.plugin(findOrCreate);
const User = new mongoose.model("User", userSchema);



// -----USING PASSPORT TO CREATE LOCAL LOGIN----
passport.use(User.createStrategy());
passport.serializeUser(function(user, done){
  done(null, user);
});
passport.deserializeUser(function(user, done){
  done(null, user);
});



// -------GOOGLE STRATEGY--------
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id },
      function (err, user) {
      return cb(err, user);
    });
  }
));


// -------FACEBOOK STRATEGY--------
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id },
      function (err, user) {
      return cb(err, user);
    });
  }
));



// -------GITHUB STRATEGY--------
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res){
  res.render("home");
});



// -----GOOGLE AUTHENTICATION-----
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile", "email"] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
});


// -----FACEBOOK AUTHENTICATION-----
app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ["email"] }));


app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});


// -----GITHUB AUTHENTICATION-----
app.get('/auth/github', passport.authenticate('github'));

app.get('/auth/github/secrets', passport.authenticate('github',
{ failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
});


app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
 User.find({"secret": {$ne: null}}, function(err, foundUser){
   if(err){
     console.log(err);
   }else{
     if (foundUser){
       res.render("secrets", {userWithSecrets: foundUser});
     }
   }
 });
});


app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});


app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user._id, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        console.log(foundUser.secret);
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});



app.post("/register", function(req, res){
  // register() module comes from passport-local-mongoose package
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if (err){
      console.log(err);
      res.redirect("/register");
    }else{
      // SETUP COOKIE WHEN USER REGISTERED AND LOGGED IN--------passport.authenticate() is from passport-local package
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.get("/login", function(req, res){
  res.render("login");
});

app.post("/login", function(req, res){
const user = new User({
  username: req.body.username,
  password: req.body.password
});
// login() comes from passport-local package
  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});


app.get("/logout", function(req, res){
  req.logout(function(err){
    if(err){
      console.log(err);
    }else{
      res.redirect("/");
    }
  });
});


app.listen(process.env.PORT || 3000, function() {
  console.log("Server is running on port 3000");
});
