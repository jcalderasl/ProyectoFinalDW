const bcrypt = require('bcrypt');
const mongoose = require('mongoose');

const saltRounds = 10;

//permite guardar
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    nombre: { type: String, required: true },
    apellido: { type: String, required: true },
    fechaNacimiento: { type: Date, required: true },
    pais: { type: String, required: true }
  });


UserSchema.pre('save', function (next) {
    if (this.isNew || this.isModified('password')) {

        const document = this;

        bcrypt.hash(document.password, saltRounds, (err, hashedPassword) => {
            if (err) {
                next(err);
            } else {
                document.password = hashedPassword;
                next();
            }
        });
    } else {
        next();
    }
});

//permite comparar
UserSchema.methods.isCorrectPassword = function (password, callback) {
    bcrypt.compare(password, this.password, function (err, same) {
        if (err) {
            callback(err);
        } else {
            callback(err, same);
        }
    });
}

//exportamos 
module.exports = mongoose.model('User', UserSchema);

