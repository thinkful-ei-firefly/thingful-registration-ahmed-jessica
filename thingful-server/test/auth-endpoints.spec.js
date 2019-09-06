const knex = require('knex')
const app = require('../src/app')
const helpers = require('./test-helpers')
const jwt = require('jsonwebtoken')

describe.only('Auth Endpoints', function() {
  let db

  const { testUsers } = helpers.makeThingsFixtures()
  const testUser = testUsers[0]

  before('make knex instance', () => {
    db = knex({
      client: 'pg',
      connection: process.env.TEST_DB_URL,
    })
    app.set('db', db)
  })

  after('disconnect from db', () => db.destroy())

  before('cleanup', () => helpers.cleanTables(db))

  afterEach('cleanup', () => helpers.cleanTables(db))

  describe(`POST /api/auth/login`, () => {
    beforeEach('insert users', () =>
      helpers.seedUsers(
        db,
        testUsers,
      )
    )

    const requiredFields = ['user_name', 'password']

    //console.log(testUser);
   requiredFields.forEach(field => {
     const loginAttemptBody = {
       user_name: testUser.user_name,
       password: testUser.password,
     }

     it(`responds with 400 required error when '${field}' is missing`, () => {
       loginAttemptBody[field] = null;

       return supertest(app)
         .post('/api/auth/login')
         .send(loginAttemptBody)
         .expect(400, {
           error: `Missing '${field}' in request body`,
         })
     })
   })

   it(`responds 400 'invalid user_name or password' when bad user_name`, () => {
     const userInvalidUser = { user_name: 'user-not', password: 'existy' }
     return supertest(app)
       .post('/api/auth/login')
       .send(userInvalidUser)
       .expect(400, { error: `Incorrect user_name or password` })
   })

   it(`responds 200 and JWT auth token using secret when valid credentials`, () => {
     const userValidCreds = {
       user_name: testUser.user_name,
       password: testUser.password,
     }
     const expectedToken = jwt.sign(
       { user_id: testUser.id },
       process.env.JWT_SECRET,
       {
         subject: testUser.user_name,
         algorithm: 'HS256',
       }
     )
     return supertest(app)
       .post('/api/auth/login')
       .send(userValidCreds)
       .expect(200, {
         authToken: expectedToken,
       })
   })

  })

  describe('POST/api/auth/register', () => {
    beforeEach('insert users', () =>
      helpers.seedUsers(
        db,
        testUsers,
      )
    )

    const newUserValidCreds = {
      user_name: 'ValidUserName',
      password: 'Abc123DoReMi!',
      full_name: 'John Doe',
      nickname: 'John'
    };

    const requiredFields = ['user_name', 'password', 'full_name'];

    it('responds with 201 created when given valid data', () => {
      return supertest(app)
        .post('/api/auth/register')
        .send(newUserValidCreds)
        .expect(201)

    })

    requiredFields.forEach(field => {
      const registerAttemptBody = {
        user_name: 'ValidUserName',
        password: 'Abc123DoReMi!',
        full_name: 'John Doe',
        nickname: 'John'
      };
      
      it(`responds with 400 Required error when ${field} is missing`, () => {
        delete registerAttemptBody[field]

        return supertest(app)
          .post('/api/auth/register')
          .send(registerAttemptBody)
          .expect(400, { error: `Missing ${field} in request body` })
      })
    })

    it('responds with 400 "Password must be longer than 8 characters" if password is too short', () => {
      const registerAttemptShortPassword = {
        user_name: 'ValidUserName',
        password: '1234567',
        full_name: 'John Doe',
        nickname: 'John'
      };

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptShortPassword)
        .expect(400, {error: 'Password must be longer than 8 characters'})
    })

    it('responds with 400 "Password must be shorter than 72 characters" if password is too long', () => {
      const registerAttemptLongPassword = {
        user_name: 'ValidUserName',
        password: '12345678910111213141516171819202122232425262728293031323334353637383940!',
        full_name: 'John Doe',
        nickname: 'John'
      };

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptLongPassword)
        .expect(400, {error: 'Password must be shorter than 72 characters'})
    })

    it('responds with 400 "Password must not start or end with empty spaces" if password begins with empty spaces', () => {
      const registerAttemptSpaceBeforePassword = {
        user_name: 'ValidUserName',
        password: ' Abc123DoReMi!',
        full_name: 'John Doe',
        nickname: 'John'
      };

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptSpaceBeforePassword)
        .expect(400, {error: 'Password must not start or end with empty spaces'})
    })

    it('responds with 400 "Password must not start or end with empty spaces" if password ends with empty spaces', () => {
      const registerAttemptSpaceAfterPassword = {
        user_name: 'ValidUserName',
        password: 'Abc123DoReMi! ',
        full_name: 'John Doe',
        nickname: 'John'
      };

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptSpaceAfterPassword)
        .expect(400, {error: 'Password must not start or end with empty spaces'})
    })

    it('responds with 400 when password is not sufficiently complex', () => {
      const registerAttemptSimplePassword = {
        user_name: 'ValidUserName',
        password: 'password!',
        full_name: 'John Doe',
        nickname: 'John'
      }; 

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptSimplePassword)
        .expect(400, {error: `Password must contain 1 upper case, lower case, number and special character`})
    })

    it('responds with 400 "User name is already taken" when user_name already exists in the database', () => {
      const registerAttemptDuplicateUser = {
        user_name: testUser.user_name,
        password: 'Abc123DoReMi!',
        full_name: 'John Doe',
        nickname: 'John'
      }; 

      return supertest(app)
        .post('/api/auth/register')
        .send(registerAttemptDuplicateUser)
        .expect(400, {error: `User name is already taken`})
    })


  })
})
