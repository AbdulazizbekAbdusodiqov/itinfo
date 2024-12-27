const { to } = require("../helpers/to_promise");
const {userJwt} = require("../services/jwt.service");

module.exports = async function (req, res, next) {
  try {
    const authorization = req.headers.authorization;
    // console.log(authorization);

    if (!authorization) {
      return res
        .status(403)
        .send({ message: "token topilmadi" });
    }
    const bearer = authorization.split(" ")[0];
    const token = authorization.split(" ")[1];
    if (bearer !== "Bearer" || !token) {
      return res
        .status(403)
        .send({ message: "User royhatdan o'tmagan (token berilmagan)" });
    }
    const [error, decodedToken] = await to(userJwt.verifyAccessToken(token));

    if (error) {
      return res.status(403).send({ message: error.message });
    }

    // console.log(decodedToken);
    req.user = decodedToken;
    next();
  } catch (error) {
    console.log(error);
    return res.status(403).send({ message: error.message });
  }
};
