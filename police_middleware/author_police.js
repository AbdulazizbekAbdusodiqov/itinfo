const { to } = require("../helpers/to_promise");
const {authorJwt} = require("../services/jwt.service");

module.exports = async function (req, res, next) {
  try {
    const authorization = req.headers.authorization;
    console.log(authorization);

    if (!authorization) {
      return res
        .status(403)
        .send({ message: "Avtor royhatdan otmagan(token topilmadi" });
    }
    const bearer = authorization.split(" ")[0];
    const token = authorization.split(" ")[1];
    if (bearer !== "Bearer" || !token) {
      return res
        .status(403)
        .send({ message: "Avtor royhatdan otmagan(token berilmagan" });
    }
    const [error, decodedToken] = await to(authorJwt.verifyAccessToken(token));

    if (error) {
      return res.status(403).send({ message: error.message });
    }

    console.log(decodedToken);
    req.author = decodedToken;
    next();
  } catch (error) {
    console.log(error);
    return res.status(403).send({ message: error.message });
  }
};
