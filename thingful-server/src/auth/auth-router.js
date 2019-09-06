/* eslint-disable strict */
const express = require('express');
const AuthService = require('./auth-service');

const authRouter = express.Router();
const jsonBodyParser = express.json();

authRouter
  .route('/login')
  .post(jsonBodyParser, (req, res, next) => {
    const { user_name, password } =  req.body;
    const loginUser = { user_name, password };
    for (const [key, value] of Object.entries(loginUser))
      if (value === null)
        return res.status(400).json({
          error: `Missing '${key}' in request body`
        });

    AuthService.getUserWithUserName(req.app.get('db'), loginUser.user_name)
      .then(user => {
        if (!user) {
          return res.status(400).json({ error: 'Incorrect user_name or password'});
        }

        return AuthService.comparePasswords(password, user.password)
          .then(passwordsMatch => {
            if(!passwordsMatch) {
              return res.status(400).json({ error: 'Incorrect user_name or password'});
            }
            const sub = user.user_name;
            const payload = { user_id: user.id};
            return res.send({authToken: AuthService.createJWT(sub, payload)});
          });

      })
      .catch(next);
  });

authRouter
  .route('/register')
  .post(jsonBodyParser, (req, res, next) => {
    
    for (const field of ['user_name', 'password', 'full_name']) {
      if (!req.body[field]) {
        return res.status(400).json( { error: `Missing ${field} in request body`});
      }
    }

    const { user_name, password, full_name, nickname } = req.body;


    const newUser = {
      user_name,
      password,
      full_name,
      nickname
    };
    return res.status(201).json(newUser);
  });

module.exports = authRouter;
