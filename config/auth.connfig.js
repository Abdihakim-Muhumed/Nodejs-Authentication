const dotenv = requi('dotenv');
dotenv.config();

module.exports = {
    secret: process.env.SECRET_KEY
}