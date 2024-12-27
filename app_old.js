const express = require("express");
const config = require("config");
const mongoose = require("mongoose");
const cookieParser = require('cookie-parser')
const PORT = config.get("port");
const mainRouter = require("./routes/index.routes");
const errorHandlerMiddleware  = require("./error_middleware/errorHandling.middleware");
const logger = require("./services/logger.service");
require('dotenv').config({path : `.env.${process.env.NODE_ENV}`})
const winston = require('winston')
const expressWinston = require('express-winston');

console.log(process.env.NODE_ENV);
console.log(process.env.secret);
console.log(config.get("secret"));


logger.log("info","Log malumotlai")
logger.error("Error malumotlar")
logger.debug("Debug malumotlar")
logger.warn("Warning malumotlar")
logger.info("Info malumotlar")

// console.trace("Trace malumotlar")
// console.table([1,2,3,4,5,6,7,8,9,10])
// console.table([["Sobir", 12],[],[]])

const app = express();
app.use(express.json());
app.use(cookieParser())

app.use(expressWinston.logger({
  transports: [
    new winston.transports.Console()
  ],
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.json()
  ),
  meta: true, // optional: control whether you want to log the meta data about the request (default to true)
  msg: "HTTP {{req.method}} {{req.url}}", // optional: customize the default logging message. E.g. "{{res.statusCode}} {{req.method}} {{res.responseTime}}ms {{req.url}}"
  expressFormat: true, // Use the default Express/morgan request formatting. Enabling this will override any msg if true. Will only output colors with colorize set to true
  colorize: false, // Color the text and status code, using the Express/morgan color palette (text: gray, status: default green, 3XX cyan, 4XX yellow, 5XX red).
  ignoreRoute: function (req, res) { return false; } // optional: allows to skip some log messages based on request and/or response
}));

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
