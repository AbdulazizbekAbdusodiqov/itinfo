const express = require("express");
const config = require("config");
const mongoose = require("mongoose");
const cookieParser = require('cookie-parser')
const PORT = config.get("port");
const mainRouter = require("./routes/index.routes");
const errorHandlerMiddleware  = require("./error_middleware/errorHandling.middleware");
const logger = require("./services/logger.service");
require('dotenv').config({path : `.env.${process.env.NODE_ENV}`})
const exHbs = require('express-handlebars')
const viewRouter = require('./routes/view.routes.js')


const hbs = exHbs.create({
  defaultLayout : "main",
  extname : "hbs"
})

const app = express();


app.use(express.json());
app.use(cookieParser())

app.engine("hbs", hbs.engine)
app.set("view engine", "hbs")
app.set('views', './views')
app.use(express.static("views"))

app.use("/", viewRouter);
app.use("/api", mainRouter);


app.use(errorHandlerMiddleware) //errorni ushlab olish uchun oxirida chaqiriladi

async function start() {
  try {
    await mongoose.connect(config.get("dbAtlasUri"));
    app.listen(PORT, () => {
      logger.info(`Server started at: http://localhost:${PORT}`);
    });
  } catch (error) {
    console.log("Malumotlar bazasiga ulanishda hatolik");
  }
}

start();
