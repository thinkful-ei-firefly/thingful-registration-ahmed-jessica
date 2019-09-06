/* eslint-disable strict */
const AuthService = require('./auth/auth-service')

function authenticateTokenJwt(req, res, next) {

  const authToken = req.get('Authorization') || '';
  let bearerToken;

  if (!authToken.toLowerCase().startsWith('bearer')) {
    return res.status(401).json({ error: 'Missing Bearer token'});
  } else {
    bearerToken = authToken.slice('bearer '.length, authToken.length);
  }

  try {
    //AuthService.verifyJwt(bearerToken);
    const payload = AuthService.verifyJwt(bearerToken);
    AuthService.getUserWithUserName(
      req.app.get('db'),
      payload.sub
    )
    .then(user => {
      if (!user)
        return res.status(401).json({error: 'Unauthorized request'})
      req.user = user;
      next()
    })
    .catch(err => {
      next(err);
    })
    //next()
  }catch (error){
    res.status(401).json({error: 'Uhauthorized request'})
  }

  /*const [tokenUserName, tokenPassword] = Buffer
    .from(basicToken, 'base64')
    .toString()
    .split(':');

  if(!tokenUserName || !tokenPassword) {
    return res.status(401).json({ error: 'Unauthorized request'});
  }

  req.app.get('db')('thingful_users')
    .where({ user_name: tokenUserName})
    .first()
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized request'});
      }

      return bcrypt.compare(tokenPassword, user.password)
        .then(passwordsMatch => {
          if(!passwordsMatch) {
            return res.status(401).json({ error: 'Unauthorized request'});
          }
          req.user = user;
          next();
        });

    })
    .catch(next);*/

}

module.exports = authenticateTokenJwt;
