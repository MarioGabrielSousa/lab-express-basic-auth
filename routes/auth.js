const express = require('express');
const router = express.Router();
const User = require('../models/User.model');
const bcrypt = require('bcryptjs');


router.get('/signup', (req, res) => {
  res.render('auth/signup');
});
router.post('/signup', (req, res) => {
  const {
    username,
    password
  } = req.body;
  //Server side validation on empty fields
  if (username === '' || password === '') {
    res.render('auth/signup', {
      errorMessage: 'Indicate username and passsword'
    });
    return;
  }
  //Server side validation on password constrain
  //Regular expressions
  const passwordRegex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  if (passwordRegex.test(password) === false) {
    res.render('auth/signup', {
      errorMessage: 'Weak password'
    });
    return;
  }
  User.findOne({
      username: username
    })
    .then((user) => {
      if (user) {
        res.render('auth/signup', {
          errorMessage: 'User already exists'
        });
        return;
      }
      //Create the user
      const saltRounds = 10;
      const salt = bcrypt.genSaltSync(saltRounds);
      const hashPassword = bcrypt.hashSync(password, salt);
      User.create({
        username,
        password: hashPassword
      }).then(() => {
        res.redirect('/');
      }).catch((error) => {
        //.code is mongoose validation error
        if (error.code === 11000) {
          res.render('auth/signup', {
            errorMessage: 'Username and email should be unique'
          });
        }
      });
    });
});
module.exports = router;
