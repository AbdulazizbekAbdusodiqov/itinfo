const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const User = require("../schemas/Users");
const { userJwt } = require("../services/jwt.service");
const Users = require("../schemas/Users");
const { to } = require("../helpers/to_promise");
const config = require("config");
const bcrypt = require("bcrypt");
const uuid = require("uuid");
const mailService = require("../services/mail.service");


const getUsers = async (req, res) => {
  try {
    const users = await User.find();
    res.send({ users });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getUserById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const user = await User.findOne({ _id: id });

    if (!user) {
      return res
        .status(400)
        .send({ message: "Bunday foydalanuvchi mavjud emas" });
    }

    res.send({ user });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addUser = async (req, res) => {
  try {
    const {
      user_name,
      user_email,
      user_password,
      user_info,
      user_is_active,
    } = req.body;

    const hashedPassword = bcrypt.hashSync(user_password,7);

    const activation_link = uuid.v4()


    const newUser = await User.create({
      user_name,
      user_email,
      user_password : hashedPassword,
      user_info,
      activation_link,
      user_is_active
    });

    await mailService.sendMailActivationCode(newUser.user_email,
      `${config.get("api_url")}/api/users/activate/${activation_link}`
    )


    res.status(201).send({ message: "Yangi foydalanuvchi qo'shildi", newUser });
  } catch (error) {
    errorHandler(error, res);
  }
};

const deleteUserById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const user = await User.deleteOne({ _id: id });

    if (!user.deletedCount) {
      return res
        .status(400)
        .send({ message: "Foydalanuvchi topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Foydalanuvchi o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

//login

const loginUser = async (req, res) => {

  try {
    const { user_email, user_password } = req.body

    const user = await User.findOne({ user_email});

    if (!user) {
      return res.status(401).send({ message: "email yoki password xato" })
    }

    const payload = {
      id: user._id,
      user_name: user.user_name,
      email: user.email,
      USER_IS_ACTIVE: user.USER_IS_ACTIVE,
    };

    const validPassword = bcrypt.compareSync(
      user_password,
      user.user_password
    );

    if (!validPassword) {
      return res.status(401).send({ message: "email yoki password xato" })
    }

    const tokens = userJwt.generateTokens(payload);

    user.refresh_token = tokens.refreshToken
    
    await user.save()

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("refresh_token_ms")
    });

    res.status(200).send({ message: "Tizimga xush kelibsiz", ...tokens });

  } catch (error) {
    errorHandler(error, res);
  }

};

//logout

const logoutUser = (req, res) => {
  try {

    const { refreshToken } = req.cookies

    if (!refreshToken) {
      return res.status(400).send({ message: "Token topilmadi" })
    }
    const user = User.findOneAndUpdate(
      { refresh_token: refreshToken },
      { refresh_token: "" },
      { new: true }
    )
    if (!user) {
      return res.status(400).send({ message: "Bunday tokenli user yo'q!" })
    }
    res.clearCookie("refreshToken");

    return res.status(201).send({ refreshToken: user.refresh_token })

  } catch (error) {
    errorHandler(error, res)
  }
}

//user refresh token


const refreshTokenUser = async (req, res) => {
  try {
    const { refreshToken } = req.cookie

    if (!refreshToken) {
      return res.status(400).send({ message: "Token topilmadi!" })
    }

    const [error, tokenFromCookie] = await to(
      userJwt.verifyRefreshToken(refreshToken)
    );

    if (error) {
      return res.status(401).send({ error: error.message })
    }
    const user = await User.findOne({ refresh_token: refreshToken });

    if (!user) {
      return res.status(404).send({ message: "User not found" })
    }

    const payload = {
      id: user._id,
      user_name: user.user_name,
      email: user.email,
      USER_IS_ACTIVE: user.USER_IS_ACTIVE,
    };


    const tokens = userJwt.generateTokens(payload);
    user.refresh_token = tokens.refreshToken
    await user.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("refresh_token_ms")
    })

    res.status(200).send({ message: "Tizimga hush kelibsiz", accessToken: tokens.accessToken });


  } catch (error) {
    errorHandler(error, res)
  }
}

// Foydalanuvchini yangilash
const updateUser = async (req, res) => {
  try {
    const id = req.params.id;
    const {
      user_name,
      user_email,
      user_password,
      user_info,
      user_photo,
      USER_IS_ACTIVE,
    } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const user = await User.updateOne(
      { _id: id },
      {
        user_name,
        user_email,
        user_password,
        user_info,
        user_photo,
        USER_IS_ACTIVE,
      }
    );

    if (!user.nModified) {
      return res.status(400).send({ message: "Foydalanuvchi yangilanmadi" });
    }

    res.send({ message: "Foydalanuvchi yangilandi", user });
  } catch (error) {
    errorHandler(error, res);
  }
};


const activateUser = async (req, res) => {
  try {
    const link  = req.params.link
    const user = await Users.findOne({ activation_link: link });

    if (!user) {
      return res.status(400).send({ message: "user topilmadi" })
    }
    if (user.user_is_active) {
      return res.status(400).send({ message: "User oldin faollashtirilgan" });
    }

    user.user_is_active = true
    await user.save()

    return res.send({ message: "User muvaffaqqiyatli faollashtirildi", is_active: user.user_is_active })

  } catch (error) {
    errorHandler(error, res)
  }
}

module.exports = {
  getUsers,
  getUserById,
  addUser,
  deleteUserById,
  updateUser,
  loginUser,
  logoutUser,
  refreshTokenUser,
  activateUser
};
