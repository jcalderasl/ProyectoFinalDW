const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const app = express();

const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const User = require('./public/user');
const jwt = require('jsonwebtoken'); // Importa la librería JWT

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

const mongo_uri = 'mongodb://127.0.0.1:27017/usuairos';

mongoose.connect(mongo_uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log(`Conectado a ${mongo_uri}`))
  .catch((e) => console.log('Error de conexión:' + e));

// Para registrar el usuario
app.post('/register', (req, res) => {
  const { username, password, nombre, apellido, fechaNacimiento, pais } = req.body;
  const user = new User({ username, password, nombre, apellido, fechaNacimiento, pais });

  user.save()
    .then(() => {
      res.status(200).send('Usuario registrado');
    })
    .catch((err) => {
      res.status(500).send('Error al registrar al usuario');
    });
});

// Para autenticar y generar el token JWT
app.post('/authenticate', (req, res) => {
  const { username, password } = req.body;
  User.findOne({ username }) // Utilizamos findOne en lugar de find para obtener un solo usuario
    .then((user) => {
      if (!user) {
        res.status(500).send('El usuario no existe');
      } else {
        user.isCorrectPassword(password, (err, result) => {
          if (err) {
            res.status(500).send('Error al autenticar');
          } else if (result) {
            const token = generateJWT(user);
            res.status(200).json({ token }); // Enviamos el token en formato JSON
          } else {
            res.status(500).send('Usuario y/o contraseña incorrectas');
          }
        });
      }
    })
    .catch((err) => {
      res.status(500).send('Error al autenticar al usuario');
    });
});

// Middleware para verificar el token JWT
const verifyJWT = (req, res, next) => {
  const token = req.query.token; // Recibimos el token como parámetro de consulta en la URL
  if (!token) {
    return res.status(401).send('Token no proporcionado en la URL');
  }

  jwt.verify(token, 'Jesus21', (err, decoded) => { // Reemplaza 'clave_secreta' con tu clave secreta real
    if (err) {
      return res.status(401).send('Token no válido');
    }
    req.user = decoded;
    next();
  });
};

// Ruta protegida que requiere el token JWT
app.get('/protected-route', verifyJWT, (req, res) => {
  res.status(200).send('Acceso concedido al Usuario: ' + req.user.username);
});

// Función para generar tokens JWT
function generateJWT(user) {
  const token = jwt.sign({ username: user.username }, 'Jesus21', { expiresIn: '1h' }); // Reemplaza 'clave_secreta' con tu clave secreta real
  return token;
}

app.listen(3000, () => {
  console.log('El servidor se inició en el puerto 3000');
});

//http://localhost:3000/protected-route?token=TU_TOKEN_JWT_AQUI
