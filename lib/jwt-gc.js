'use strict';
const passportJwt = require('passport-jwt');
const util = require('util');
function CustomJwtStrategy(options, verify) {
    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';
    options.jwtFromRequest = passportJwt.ExtractJwt.fromAuthHeaderAsBearerToken();
    passportJwt.Strategy.call(this, options, verify);
}
util.inherits(CustomJwtStrategy, passportJwt.Strategy);

module.exports = {
    Strategy: CustomJwtStrategy
};
