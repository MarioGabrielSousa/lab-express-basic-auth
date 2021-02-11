require('dotenv').config();

const cookieParser = require('cookie-parser');
const express = require('express');
const favicon = require('serve-favicon');
const hbs = require('hbs');
const mongoose = require('mongoose');
const logger = require('morgan');
const path = require('path');
const session = require('express-session');
const MongoStore = require('connect-mongo')(session);

const app_name = require('./package.json').name;
const debug = require('debug')(`${app_name}:${path.basename(__filename).split('.')[0]}`);

const app = express();

// require database configuration
require('./configs/db.config');

// Middleware Setup
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// Express View engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(favicon(path.join(__dirname, 'public', 'images', 'favicon.ico')));



//Express session setup
app.use(
    session({
      secret: process.env.SESSION_SECRET,
      cookie: {
        sameSite: true, //regardless if Im using a safe domain or not, it's a safe site to send cookies
        httpOnly: true,
        maxAge: 60000
      },
      rolling: true,
      store: new MongoStore({
        mongooseConnection: mongoose.connection,
        ttl: 60 * 60 * 24 //60sec * 60min * 24h
      })
    }));
  



// default value for title local
app.locals.title = 'The Most Amazing Site – EVER!';

const index = require('./routes/index.routes');
app.use('/', index);

const auth = require('./routes/auth.js');
app.use('/', auth);

module.exports = app;
