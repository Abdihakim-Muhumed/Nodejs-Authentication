const express = require("express");
const cors = require("cors");

const app = express()

const corsOptions = {
    origin: "http://localhost:8081",
}

app.use(cors(corsOptions));

app.use(express.json());

app.use(express.urlencoded({extended: true}));

const db =  require("./models")
const Role = db.role
db.sequelize.sync({force: true}).then(() => {
    console.log('Drop and Resync DB');
    initial();
})

function initial() {
    Role.create({
        id: 1,
        name: "user"
    });
    Role.create({
        id: 2,
        name: "moderator"
    });
    Role.create({
        id: 3,
        name: "admin"
    });
}

app.get("/", (req, res) => {
    res.json({
        message: "Welcome to Nodejs Authentication app.",
    })
});


require("./routes/auth.routes")(app);
require("./routes/user.routes")(app);

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server is running on port http://localhost:${PORT}/`);
});