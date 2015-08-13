var express = require('express');
var router = express.Router()

router.get('/', function(req, res){
  res.render('index', {
    title: 'Express',
    user: req.user
  });
});

router.get('/login', function(req, res) {
  console.log("login user--", req.user)
  res.render('login', {
    user: req.user
  });
});

router.get('/profile', function(req, res) {
  if(req.user){
    res.render('profile', {
      user: req.user
    });
  } else {
    req.flash('info', 'User not login, please login first');
    res.redirect('/login');
  }
});

router.post('/login',
  passport.authenticate('local', { successRedirect: '/',
                                   failureRedirect: '/login',
                                   failureFlash: true })
);

router.get('/signup', function(req, res) {
  res.render('signup', {
    user: req.user
  });
});

router.post('/signup', function(req, res, next) {
  var user = new User({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password
    });

    if(user.username =='' || user.email == '' || user.password == ''){
      req.flash('info', 'All field are mandetory');
      return res.redirect('/signup');
    }
  
    if(user.password != req.body.confirm){
      req.flash('error', 'Password not match.');
      return res.redirect('/signup');
    }

  user.save(function(err) {
    if (err) return next(err);
    // req.logIn(user, function(err) {
      req.flash('info', 'Your account has been created successfully.');
      res.redirect('/');
    // });
  });
});

router.get('/logout', function(req, res){
  req.logout();
  req.flash('info', 'Your are successfully logout.');
  res.redirect('/');
});

router.get('/forgot', function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});

router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/forgot');
        }

        user.resetPasswordToken = token;
        console.log("user.resetPasswordToken --", user.resetPasswordToken)
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        console.log("user.resetPasswordExpires ---", user.resetPasswordExpires)

        user.save(function(err) {
          console.log("Inside Save")
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport('SMTP', {
        service: 'gmail',
        auth: {
          user: 'samir.katurde@raweng.com',
          pass: '@ganita1'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'samir.katurde@raweng.com',
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      console.log("mailOptions --", mailOptions)
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err){
      console.log("Err--", err)
      return next(err);  
    }
    res.redirect('/forgot');
  });
});

router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});

router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        if(user.password != req.body.confirm){
          req.flash('error', 'Password not match.');
          return res.redirect('/reset/'+req.params.token);
        }

        user.save(function(err) {
          // req.logIn(user, function(err) {
          //   done(err, user);
          // });
          req.flash('success', 'Password has been successfully updated');
          res.redirect('/login');
        });
      });
    }/*,
    function(user, done) {
      console.log("user password reset --", user)
      var smtpTransport = nodemailer.createTransport('SMTP', {
        service: 'gmail',
        auth: {
          user: 'samir.katurde@raweng.com',
          pass: '@ganita1'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'samir.katurde@raweng.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success', 'Success! Your password has been changed.');
        done(err);
      });
    }*/
  ], function(err) {
    res.redirect('/');
  });
});

module.exports = router