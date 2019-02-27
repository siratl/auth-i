const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');

const Users = require('./users/usersModel');

const server = express();

const sessionConfig = {
  name: 'dreamer',
  secret: 'the lady dreams, accurately',
  cookie: {
    maxAge: 1000 * 60 * 20, // in ms
    secure: false,
  },
  httpOnly: true,
  resave: false,
  saveUninitialized: false,
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));

server.get('/', (req, res) => {
  res.send('Server is Running!');
});

//**************** CREATE USER *********************/
server.post('/api/register', (req, res) => {
  let user = req.body;

  const hash = bcrypt.hashSync(user.password, 16);

  user.password = hash;

  Users.add(user)
    .then(savedUser => {
      res.status(201).json(savedUser);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//**************** AUTHENTICATE USER *********************/
server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check that passwords match

      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//*********** LISTS USERS ON AUTHENTICATION **************/
function restricted(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({
      errorMessage:
        'Invalid Credentials, Please provide a valid username and password.',
    });
  }
}

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//*********** PORT **************/
const port = 4444;
server.listen(port, () =>
  console.log(`\n***** Running on port: ${port} ****\n`),
);
