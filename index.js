const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session'); //1
const KnexSessionStore = require('connect-session-knex')(session);
// KnexSessionStore returns a function that you call passing session which returns another function

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfig = {
  //3
  name: 'monkey',
  secret: 'keep it secret, keep it safe',
  cookie: {
    maxAge: 1000 * 60 * 60, // in ms
    secure: false // used over https only (true on deploy)
  },
  httpOnly: true, // cannot the user access the cookie from js using document.cookie
  resave: false,
  saveUninitialized: false, // GDPR laws against setting cookies automatically
  store: new KnexSessionStore({
    knex: db,
    tablename: 'sessions',
    createtable: true
  })
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); //2

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // generate hash from user's password
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n rounds of hashing
  // override user.password with hash
  user.password = hash;

  Users.add(user)
    .then(saved => {
      req.session.server = saved;
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user; //4
        res
          .status(200)
          .json({ message: `Welcome ${user.username}!, have a cookie` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

//4
function restricted(req, res, next) {
  if (req.session && req.session.user) {
    next();
  } else {
    res.status(401).json({ message: 'You shall not pass.' });
  }
}

// function restricted(req, res, next) {
//   const { username, password } = req.headers;

//   if (username && password) {
//     Users.findBy({ username })
//       .first()
//       .then(user => {
//         if (user && bcrypt.compareSync(password, user.password)) {
//           next();
//         } else {
//           res.status(401).json({ message: 'Invalid Credentials' });
//         }
//       })
//       .catch(error => {
//         res.status(500).json({ message: 'An unexpected error occured' });
//       });
//   } else {
//     res.status(400).json({ message: 'No credentials provided' });
//   }

// axios.get(url, { headers: {username, pasword}})

// protect this route, only authenticated users should see it
server.get('/api/users', restricted, (req, res) => {
  // roles(['sales', 'admin', 'marketing']
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

//, only('frodo')
function only(username) {
  return function(req, res, next) {
    if (username === req.headers.username) {
      next();
    } else {
      res.status(403).json({ message: `you are not ${username}` });
    }
  };
}

// invalidates the session
server.get('/api/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send('You can checkout');
      } else {
        res.send('Bye');
      }
    });
  } else {
    res.end();
  }
});

// refresh server

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
