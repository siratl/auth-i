const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const Users = require('./users/usersModel');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

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
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        // check that passwords match

        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({
            errorMessage:
              'Invalid Credentials, Please provide a valid username and password.',
          });
        }
      })
      .catch(error => {
        res.status(500).json({ errorMessage: 'Unexpected Server Error!' });
      });
  } else {
    res.status(400).json({ errorMessage: 'No credentials provided' });
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
