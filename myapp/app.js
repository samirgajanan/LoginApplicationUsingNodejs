var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session')
var mongoose = require('mongoose');
    nodemailer = require('nodemailer');
    passport = require('passport');           // First part of passport configuration
var LocalStrategy = require('passport-local').Strategy;  // First part of passport configuration
    bcrypt = require('bcrypt-nodejs');
    async = require('async');
    crypto = require('crypto');
    flash = require('express-flash');
    GoogleStrategy = require('passport-google').Strategy;

// passport.use(new GoogleStrategy({
//   returnURL: 'http://localhost:4000/login',
//   realm: 'http://localhost:4000'
//   },
//   function(identifier, profile, done) {
//     console.log("Samir 1")
//     // asynchronous verification, for effect...
//     process.nextTick(function () {
//     // To keep the example simple, the user's Google profile is returned to
//     // represent the logged-in user. In a typical application, you would want
//     // to associate the Google account with a user record in your database,
//     // and return that user instead.
//     profile.identifier = identifier;
//     console.log("Samir 111")
//     return done(null, profile);
//     });
//   }
// ));


    // Passport configuration ... First part of passport configuration
    // Call when user want to sign-in
passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user, { message: 'You have successfully login.' });
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

    // it allows you to stay logged-in when navigating between different pages within your application. .. Third part of passport configuration
    // Call when user want to sign-in
passport.serializeUser(function(user, done) {
  done(null, user.id);
});


  // Third part of passport configuration
  // Call when user want to sign-in
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

    // Define User Schema
var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date
});

    // Encrypt User Password
userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

    // password verification when user tries to sign-in
userSchema.methods.comparePassword = function(candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

    // Here convert userSchema to Model
User = mongoose.model('User', userSchema);

    // Actually connect to mongodb
mongoose.connect('localhost');

app = express();

var route = require('./routes/index');

    // Add Middleware to Express configuration
app.set('port', process.env.PORT || 4000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
app.use(session({ secret: 'session secret key' }));
app.use(flash());
app.use(passport.initialize());   // Second part of passport configuration
app.use(passport.session());      // Second part of passport configuration
app.use(express.static(path.join(__dirname, 'public')));
app.use('/',route)

    // Routes
// app.get('/auth/google', passport.authenticate('google'));

// app.get('http://localhost:4000/login', 
//   passport.authenticate('google'));

// app.get('/', function(req, res){
//   res.render('index', {
//     title: 'Express',
//     user: req.user
//   });
// });

// app.get('/login', function(req, res) {
//   res.render('login', {
//     user: req.user
//   });
// });

// app.get('/profile', function(req, res) {
//   if(req.user){
//     res.render('profile', {
//       user: req.user
//     });
//   } else {
//     req.flash('info', 'User not login, please login first');
//     res.redirect('/login');
//   }
// });

// app.post('/login', function(req, res, next) {
//   passport.authenticate('local', function(err, user, info) {
//     if (err) return next(err)
//     if (!user) {
//       return res.redirect('/login')
//     }
//     req.logIn(user, function(err) {
//       if (err) return next(err);
//       return res.redirect('/');
//     });
//   })(req, res, next);
// });

// app.post('/login',
//   passport.authenticate('local', { successRedirect: '/',
//                                    failureRedirect: '/login',
//                                    failureFlash: true })
// );

// app.get('/signup', function(req, res) {
//   res.render('signup', {
//     user: req.user
//   });
// });

// app.post('/signup', function(req, res, next) {
//   var user = new User({
//       username: req.body.username,
//       email: req.body.email,
//       password: req.body.password
//     });

//     if(user.username =='' || user.email == '' || user.password == ''){
//       req.flash('info', 'All field are mandetory');
//       return res.redirect('/signup');
//     }
  
//     if(user.password != req.body.confirm){
//       req.flash('error', 'Password not match.');
//       return res.redirect('/signup');
//     }

//   user.save(function(err) {
//     if (err) return next(err);
//     // req.logIn(user, function(err) {
//       req.flash('info', 'Your account has been created successfully.');
//       res.redirect('/');
//     // });
//   });
// });

// app.get('/logout', function(req, res){
//   req.logout();
//   req.flash('info', 'Your are successfully logout.');
//   res.redirect('/');
// });

// app.get('/forgot', function(req, res) {
//   res.render('forgot', {
//     user: req.user
//   });
// });

// app.post('/forgot', function(req, res, next) {
//   async.waterfall([
//     function(done) {
//       crypto.randomBytes(20, function(err, buf) {
//         var token = buf.toString('hex');
//         done(err, token);
//       });
//     },
//     function(token, done) {
//       User.findOne({ email: req.body.email }, function(err, user) {
//         if (!user) {
//           req.flash('error', 'No account with that email address exists.');
//           return res.redirect('/forgot');
//         }

//         user.resetPasswordToken = token;
//         user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

//         user.save(function(err) {
//           done(err, token, user);
//         });
//       });
//     },
//     function(token, user, done) {
//       var smtpTransport = nodemailer.createTransport('SMTP', {
//         service: 'gmail',
//         auth: {
//           user: 'samir.katurde@raweng.com',
//           pass: '@ganita1'
//         }
//       });
//       var mailOptions = {
//         to: user.email,
//         from: 'samir.katurde@raweng.com',
//         subject: 'Node.js Password Reset',
//         text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
//           'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
//           'http://' + req.headers.host + '/reset/' + token + '\n\n' +
//           'If you did not request this, please ignore this email and your password will remain unchanged.\n'
//       };
//       smtpTransport.sendMail(mailOptions, function(err) {
//         req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
//         done(err, 'done');
//       });
//     }
//   ], function(err) {
//     if (err){
//       console.log("Err--", err)
//       return next(err);  
//     }
//     res.redirect('/forgot');
//   });
// });

// app.get('/reset/:token', function(req, res) {
//   User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
//     if (!user) {
//       req.flash('error', 'Password reset token is invalid or has expired.');
//       return res.redirect('/forgot');
//     }
//     res.render('reset', {
//       user: req.user
//     });
//   });
// });

// app.post('/reset/:token', function(req, res) {
//   async.waterfall([
//     function(done) {
//       User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
//         if (!user) {
//           req.flash('error', 'Password reset token is invalid or has expired.');
//           return res.redirect('back');
//         }

//         user.password = req.body.password;
//         user.resetPasswordToken = undefined;
//         user.resetPasswordExpires = undefined;
//         if(user.password != req.body.confirm){
//           req.flash('error', 'Password not match.');
//           return res.redirect('/reset/'+req.params.token);
//         }

//         user.save(function(err) {
//           // req.logIn(user, function(err) {
//           //   done(err, user);
//           // });
//           req.flash('success', 'Password has been successfully updated');
//           res.redirect('/login');
//         });
//       });
//     }/*,
//     function(user, done) {
//       console.log("user password reset --", user)
//       var smtpTransport = nodemailer.createTransport('SMTP', {
//         service: 'gmail',
//         auth: {
//           user: 'samir.katurde@raweng.com',
//           pass: '@ganita1'
//         }
//       });
//       var mailOptions = {
//         to: user.email,
//         from: 'samir.katurde@raweng.com',
//         subject: 'Your password has been changed',
//         text: 'Hello,\n\n' +
//           'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
//       };
//       smtpTransport.sendMail(mailOptions, function(err) {
//         req.flash('success', 'Success! Your password has been changed.');
//         done(err);
//       });
//     }*/
//   ], function(err) {
//     res.redirect('/');
//   });
// });

app.listen(app.get('port'), function() {
  console.log('Express server listening on port ' + app.get('port'));
});