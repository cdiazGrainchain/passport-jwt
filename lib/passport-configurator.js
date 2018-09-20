// Copyright IBM Corp. 2014,2016. All Rights Reserved.
// Node module: loopback-component-passport
// This file is licensed under the Artistic License 2.0.
// License text available at https://opensource.org/licenses/Artistic-2.0

'use strict';

var SG = require('strong-globalize');
var g = SG();

var loopback = require('loopback');
var passport = require('passport');
var _ = require('underscore');
//Mods GC
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt');
if (bcrypt && typeof bcrypt.compare !== 'function') {
    bcrypt = require('bcryptjs');
}
//FIN GC

module.exports = PassportConfigurator;

/**
 * The passport configurator
 * @param {Object} app The LoopBack app instance
 * @returns {PassportConfigurator}
 * @constructor
 * @class
 */
function PassportConfigurator(app) {
  if (!(this instanceof PassportConfigurator)) {
    return new PassportConfigurator(app);
  }
  this.app = app;
}

/**
 * Set up data models for user identity/credential and application credential
 * @options {Object} options Options for models
 * @property {Model} [userModel] The user model class
 * @property {Model} [userCredentialModel] The user credential model class
 * @property {Model} [userIdentityModel] The user identity model class
 * @end
 */
PassportConfigurator.prototype.setupModels = function(options) {
  options = options || {};
  // Set up relations
  //Mods GC
  this.userModel = loopback.getModelByType(this.app.models.Member);
  this.userCredentialModel = options.userCredentialModel ||
    loopback.getModelByType(this.app.models.UserCredential);
  this.userIdentityModel = options.userIdentityModel ||
    loopback.getModelByType(this.app.models.UserIdentity);

  if (!this.userModel.relations.identities) {
    this.userModel.hasMany(this.userIdentityModel, {as: 'identities'});
  } else {
    this.userIdentityModel = this.userModel.relations.identities.modelTo;
  }

 if (!this.userModel.relations.credentials) {
    this.userModel.hasMany(this.userCredentialModel, {as: 'credentials'});
  } else {
    this.userCredentialModel = this.userModel.relations.credentials.modelTo;
  }

  if (!this.userIdentityModel.relations.user) {
    this.userIdentityModel.belongsTo(this.userModel, {as: 'user'});
  }

  if (!this.userCredentialModel.relations.user) {
    this.userCredentialModel.belongsTo(this.userModel, {as: 'user'});
  }
};

/**
 * Initialize the passport configurator
 * @param {Boolean} noSession Set to true if no session is required
 * @returns {Passport}
 */
PassportConfigurator.prototype.init = function(noSession) {
  var self = this;
  self.app.middleware('session:after', passport.initialize());

  if (!noSession) {
    self.app.middleware('session:after', passport.session());

    // Serialization and deserialization is only required if passport session is
    // enabled

 passport.serializeUser(function(user, done) {
      done(null, user.id);
    });

    passport.deserializeUser(function(id, done) {
      // Look up the user instance by id
      self.userModel.findById(id, function(err, user) {
        if (err || !user) {
          return done(err, user);
        }
        user.identities(function(err, identities) {
          user.profiles = identities;
          user.credentials(function(err, accounts) {
            user.accounts = accounts;
            done(err, user);
          });
        });
      });
    });
  }

  return passport;
};

PassportConfigurator.prototype.configureProvider = function(name, options) {
  var self = this;
  options = options || {};
  var link = options.link;
  var AuthStrategy = require(options.module)[options.strategy || 'Strategy'];

  if (!AuthStrategy) {
    AuthStrategy = require(options.module);
  }

  var authScheme = options.authScheme;
  if (!authScheme) {
    // Guess the authentication scheme
    if (options.consumerKey) {
      authScheme = 'oAuth1';
    } else if (options.realm) {
      authScheme = 'OpenID';
    } else if (options.clientID) {
      authScheme = 'oAuth 2.0';
    } else if (options.usernameField) {
      authScheme = 'local';
    } else {
      authScheme = 'local';
    }
  }
  var provider = options.provider || name;
  var clientID = options.clientID;
  var clientSecret = options.clientSecret;
  var callbackURL = options.callbackURL;
  var authPath = options.authPath || ((link ? '/link/' : '/auth/') + name);
  var callbackPath = options.callbackPath || ((link ? '/link/' : '/auth/') +
    name + '/callback');
  var callbackHTTPMethod = options.callbackHTTPMethod !== 'post' ? 'get' : 'post';

  // remember returnTo position, set by ensureLoggedIn
  var successRedirect = function(req, accessToken) {
    if (!!req && req.session && req.session.returnTo) {
      var returnTo = req.session.returnTo;
      delete req.session.returnTo;
      return appendAccessToken(returnTo, accessToken);
    }
    return appendAccessToken(options.successRedirect, accessToken) ||
      (link ? '/link/account' : '/auth/account');
  };

  var appendAccessToken = function(url, accessToken) {
    if (!accessToken) {
      return url;
    }
    return url + '?access-token=' + accessToken.id + '&user-id=' + accessToken.userId;
  };

  var failureRedirect = options.failureRedirect ||
    (link ? '/link.html' : '/login.html');
  var scope = options.scope;
  var authType = authScheme.toLowerCase();

  var session = !!options.session;

  var loginCallback = options.loginCallback || function(req, done) {
    return function(err, user, identity, token) {
      var authInfo = {
        identity: identity,
      };
      if (token) {
        authInfo.accessToken = token;
      }
      done(err, user, authInfo);
    };
  };

  var strategy;
  switch (authType) {
    case 'ldap':
      strategy = new AuthStrategy(_.defaults({
        usernameField: options.usernameField || 'username',
        passwordField: options.passwordField || 'password',
        session: options.session, authInfo: true,
        passReqToCallback: true,
      }, options),
        function(req, user, done) {
          if (user) {
            var LdapAttributeForUsername = options.LdapAttributeForUsername || 'cn';
            var LdapAttributeForMail = options.LdapAttributeForMail || 'mail';
            var externalId = user[options.LdapAttributeForLogin || 'uid'];
            var email = [].concat(user[LdapAttributeForMail])[0];
            var profile = {
              username: [].concat(user[LdapAttributeForUsername])[0],
              id: externalId,
            };
            if (!!email) {
              profile.emails = [{value: email}];
            }
            var OptionsForCreation = _.defaults({
              autoLogin: true,
            }, options);
            self.userIdentityModel.login(provider, authScheme, profile, {},
              OptionsForCreation, loginCallback(req, done));
          } else {
            done(null);
          }
        }
      );
      break;
    case 'local':
     strategy = new AuthStrategy(_.defaults({
        usernameField: options.usernameField || 'username',
        passwordField: options.passwordField || 'password',
        session: options.session, authInfo: true,
      }, options),
        function(username, password, done) {
          var query = {
            where: {
              or: [
                {username: username},
                {email: username},
              ],
            },
          };
          self.userModel.findOne(query, function(err, user) {
            if (err)
              return done(err);

            var errorMsg = g.f('Invalid username/password or email has not been verified');
            if (user) {
              var u = user.toJSON();
              delete u.password;
              var userProfile = {
                provider: 'local',
                id: u.id,
                username: u.username,
                emails: [
                  {
                    value: u.email,
                    },
                ],
                status: u.status,
                accessToken: null,
              };

              // If we need a token as well, authenticate using Loopbacks
              // own login system, else defer to a simple password check
              //will grab user info from providers.json file.  Right now
              //this only can use email and username, which are the 2 most common
              var login = function(creds) {
                self.userModel.login(creds,
                  function(err, accessToken) {
                    if (err) {
                      return err.code === 'LOGIN_FAILED' ?
                          done(null, false, {message: g.f('Failed to create token.')}) :
                          done(err);
                    }
                    if (accessToken && user.emailVerified) {
                      userProfile.accessToken = accessToken;
                      done(null, userProfile, {accessToken: accessToken});
                    } else {
                      done(null, false, {message: g.f('Failed to create token.')});
                    }
                  });
              };
              if (options.setAccessToken) {
                switch (options.usernameField) {
                  case  'email':
                    login({email: username, password: password});
                    break;
                  case 'username':
                    login({username: username, password: password});
                    break;
                }
              } else {
                return user.hasPassword(password, function(err, ok) {
                  // Fail to login if email is not verified or invalid username/password.
                  // Unify error message in order not to give indication about the error source for
                  // security purposes.
                  if (ok && user.emailVerified)
                    return done(null, userProfile);

                  done(null, false, {message: errorMsg});
                });
              }
            } else {
              done(null, false, {message: errorMsg});
            }
          });
        }
      );
      break;
    case 'oauth':
    case 'oauth1':
    case 'oauth 1.0':
      strategy = new AuthStrategy(_.defaults({
        consumerKey: options.consumerKey,
        consumerSecret: options.consumerSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
        function(req, token, tokenSecret, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(
                req.user.id, provider, authScheme, profile,
                {token: token, tokenSecret: tokenSecret}, options, done);
            } else {
              done(g.f('No user is logged in'));
            }
          } else {
            self.userIdentityModel.login(provider, authScheme, profile,
              {
                token: token,
                tokenSecret: tokenSecret,
              }, options, loginCallback(req, done));
          }
        }
      );
      break;
    case 'openid':
      strategy = new AuthStrategy(_.defaults({
        returnURL: options.returnURL,
        realm: options.realm,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
      function(req, identifier, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(
                req.user.id, provider, authScheme, profile,
                {identifier: identifier}, options, done);
            } else {
              done(g.f('No user is logged in'));
            }
          } else {
            self.userIdentityModel.login(provider, authScheme, profile,
              {identifier: identifier}, options, loginCallback(req, done));
          }
        }
      );
      break;
    case 'openid connect':
      strategy = new AuthStrategy(_.defaults({
        clientID: clientID,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
        function(req, accessToken, refreshToken, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(
                req.user.id, provider, authScheme, profile,
                {
                   accessToken: accessToken,
                  refreshToken: refreshToken,
                }, options, done);
            } else {
              done(g.f('No user is logged in'));
            }
          } else {
            self.userIdentityModel.login(provider, authScheme, profile,
              {accessToken: accessToken, refreshToken: refreshToken},
              options, loginCallback(req, done));
          }
        }
      );
      break;
    case 'saml':
      strategy = new AuthStrategy(_.defaults({
        passReqToCallback: true,
      }, options),
        function(req, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(req.user.id, name, authScheme,
                profile, {}, options, done);
            } else {
              done('No user is logged in');
            }
          } else {
            self.userIdentityModel.login(name, authScheme, profile, {},
              options, loginCallback(req, done));
          }
        }
      );
      break;
    //MOD GC
    case 'saml-gc':
      console.log('### Entra a saml-gc');
      strategy = new AuthStrategy(_.defaults({
         usernameField: options.usernameField || 'username',
         passwordField: options.passwordField || 'password',
         passReqToCallback: true,
      }, options),
        function(req, profile, done, username, password) {
          var query = {
            where: {
              or: [
                {email: username},
                {password: username},
              ],
            },
          };
          self.userModel.findOne(query, function(err, user) {
              if (!user)
                return done(err);
              
              var u = user.toJSON();
              
              /* Verificar status aprobado o auto-aprobado */
              if(u.status!='Approved' && u.status!='AutoApproved'){
                return done(err);
              }

              /* Encryptar password Bcrypt y verificar si es correcto */
              if (u.password && password) {
                  bcrypt.compare(password, u.password, function(err, isMatch) {
                     if(isMatch){
                      self.userIdentityModel.login(name, authScheme, profile, {},
                      options, loginCallback(req, done));
                     }else{
                      return done(err);
                     }
                  });
              } else {
                  return done(err);
              }

          });
      }
      );
    break;
    //FIN GC
    default:
      strategy = new AuthStrategy(_.defaults({
        clientID: clientID,
        clientSecret: clientSecret,
        callbackURL: callbackURL,
        passReqToCallback: true,
      }, options),
        function(req, accessToken, refreshToken, profile, done) {
          if (link) {
            if (req.user) {
              self.userCredentialModel.link(
                req.user.id, provider, authScheme, profile,
                {
                  accessToken: accessToken,
                  refreshToken: refreshToken,
                }, options, done);
            } else {
              done(g.f('No user is logged in'));
            }
          } else {
            self.userIdentityModel.login(provider, authScheme, profile,
              {accessToken: accessToken, refreshToken: refreshToken},
              options, loginCallback(req, done));
          }
        }
      );
  }

  passport.use(name, strategy);

  var defaultCallback = function(req, res, next) {
    // The default callback
    passport.authenticate(name, _.defaults({session: session},
      options.authOptions), function(err, user, info) {
        if (err) {
          return next(err);
        }
        if (!user) {
          if (!!options.json) {
            return res.status(401).json(g.f('authentication error'));
          }
          if (options.failureQueryString && info) {
            return res.redirect(appendErrorToQueryString(failureRedirect, info));
          }
          //return res.redirect(failureRedirect);
          return res.sendStatus(401);
        }
        if (session) {
          req.logIn(user, function(err) {
            if (err) {
              return next(err);
            }
            if (info && info.accessToken) {
              if (!!options.json) {
                return res.json({
                  'access_token': info.accessToken.id,
                  userId: user.id,
                });
              } else {
                res.cookie('access_token', info.accessToken.id,
                  {
                    signed: req.signedCookies ? true : false,
                  // maxAge is in ms
                    maxAge: 1000 * info.accessToken.ttl,
                    domain: (options.domain) ? options.domain : null,
                  });
                res.cookie('userId', user.id.toString(), {
                  signed: req.signedCookies ? true : false,
                  maxAge: 1000 * info.accessToken.ttl,
                  domain: (options.domain) ? options.domain : null,
                });
              }
            }
            //return res.redirect(successRedirect(req));
            if(session){
              return res.sendStatus(200);
            }else{
              return res.sendStatus(401);
            }

          });
        } else {
          if (info && info.accessToken) {
            if (!!options.json) {
              return res.json({
                'access_token': info.accessToken.id,
                userId: user.id,
              });
            } else {
              res.cookie('access_token', info.accessToken.id, {
                 signed: req.signedCookies ? true : false,
                maxAge: 1000 * info.accessToken.ttl,
              });
              res.cookie('userId', user.id.toString(), {
                signed: req.signedCookies ? true : false,
                maxAge: 1000 * info.accessToken.ttl,
              });
            }
          }
          return res.redirect(successRedirect(req, info.accessToken));
        }
      })(req, res, next);
  };
  /*
   * Setup the authentication request URLs.
   */
  if (authType === 'local') {
    self.app.post(authPath, passport.authenticate(
      name, options.fn || _.defaults({
        successReturnToOrRedirect: options.successReturnToOrRedirect,
        successRedirect: options.successRedirect,
        failureRedirect: options.failureRedirect,
        successFlash: options.successFlash,
        failureFlash: options.failureFlash,
        scope: scope, session: session,
      }, options.authOptions)));
  } else if (authType === 'ldap') {
    var ldapCallback = options.customCallback || defaultCallback;
    self.app.post(authPath, ldapCallback);
  } else if (link) {
    self.app.get(authPath, passport.authorize(name, _.defaults({
      scope: scope,
      session: session,
    }, options.authOptions)));
  //MOD GC
  } else {
    self.app.post(authPath, passport.authenticate(name, _.defaults({
      scope: scope,
      session: session,
      successRedirect: options.successRedirect,
    }, options.authOptions)));
  }
  //FIN GC

  /*
   * Setup the authentication callback URLs.
   */
  if (link) {
    self.app[callbackHTTPMethod](callbackPath, passport.authorize(name, _.defaults({
      session: session,
        // successReturnToOrRedirect: successRedirect,
      successRedirect: successRedirect(),
      failureRedirect: failureRedirect,
    }, options.authOptions)),
      // passport.authorize doesn't handle redirect
      function(req, res, next) {
        res.redirect(successRedirect(req));
      }, function(err, req, res, next) {
        if (options.failureFlash) {
          if (typeof req.flash !== 'function') {
            next(new TypeError(g.f('{{req.flash}} is not a function')));
           }
          var flash = options.failureFlash;
          if (typeof flash === 'string') {
            flash = {type: 'error', message: flash};
          }

          var type = flash.type || 'error';
          var msg = flash.message || err.message;
          if (typeof msg === 'string') {
            req.flash(type, msg);
          }
        }

        if (options.failureQueryString) {
          return res.redirect(appendErrorToQueryString(failureRedirect, err));
        }

        res.redirect(failureRedirect);
      });
  } else {
    var customCallback = options.customCallback || defaultCallback;
    // Register the path and the callback.
    self.app[callbackHTTPMethod](callbackPath, customCallback);
  }

  function appendErrorToQueryString(url, err) {
    var hasQueryString = (url.indexOf('?') !== -1);
    var separator = (hasQueryString) ? '&' : '?';
    var fieldValuePair = 'error=' + encodeURIComponent(err);
     var queryString = url + separator + fieldValuePair;
    return queryString;
  }

  return strategy;
};
