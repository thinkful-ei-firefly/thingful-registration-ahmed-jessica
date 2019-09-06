'use strict';
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../config');
const xss = require('xss')

const AuthService = {

  hasUserWithUserName(db, user_name) {
     return db('thingful_users')
       .where({ user_name })
       .first()
       .then(user => !!user)
   },

   insertUser(db, newUser) {
     return db
       .insert(newUser)
       .into('thingful_users')
       .returning('*')
       .then(([user]) => user)
   },

  getUserWithUserName(db, user_name) {
    return db('thingful_users')
      .where({user_name})
      .first();
  },

  comparePasswords(password, hash) {
    return bcrypt.compare(password, hash);
  },

  createJWT(subject, payload) {
    return jwt.sign(payload, config.JWT_SECRET, {
      subject,
      algorithm: 'HS256'
    });
  },
  
  verifyJwt(token) {
    return jwt.verify(token, config.JWT_SECRET, {algorithm: 'HS256'})
  },
     hashPassword(password) {
   return bcrypt.hash(password, 12)
 },
   serializeUser(user) {
     return {
       id: user.id,
       full_name: xss(user.full_name),
       user_name: xss(user.user_name),
       nickname: xss(user.nick_name),
       date_created: new Date(user.date_created),
     }
   },
};

module.exports = AuthService;
