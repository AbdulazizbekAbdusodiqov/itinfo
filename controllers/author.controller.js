const mongoose = require("mongoose");
const { errorHandler } = require("../helpers/error_handler");
const { to } = require("../helpers/to_promise");
const Author = require("../schemas/Author");
const { authorValidation } = require("../validation/author.validation");
const bcrypt = require("bcrypt");
const config = require("config");
const { authorJwt } = require("../services/jwt.service");
const uuid = require("uuid")
const mailService = require("../services/mail.service")

const getAuthors = async (req, res) => {
  try {
    const authors = await Author.find();
    res.send({ authors });
  } catch (error) {
    errorHandler(error, res);
  }
};

const getAuthorById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const author = await Author.findOne({ _id: id });

    if (!author) {
      return res.status(400).send({ message: "Bunday muallif mavjud emas" });
    }

    res.send({ author });
  } catch (error) {
    errorHandler(error, res);
  }
};

const addAuthor = async (req, res) => {
  try {
    // const { error, value } = authorValidation(req.body);
    // if (error) {
    //   return res.status(400).send({ message: error.message });
    // }

    const {
      author_first_name,
      author_last_name ,
      author_nick_name ,
      author_email ,
      author_phone ,
      author_password, 
      author_position
    } = req.body;

    const hashedPassword = bcrypt.hashSync(author_password, 7);

    const activation_link = uuid.v4()

    const newAuthor = await Author.create({
      author_first_name,
      author_last_name ,
      author_nick_name ,
      author_email ,
      author_phone ,
      author_password : hashedPassword, 
      activation_link,
      author_position
    });

    await mailService.sendMailActivationCode(newAuthor.author_email,
      `${config.get("api_url")}/api/author/activate/${activation_link}`
    );

    res.status(201).send({ message: "Yangi muallif qo'shildi", newAuthor });
  } catch (error) {
    errorHandler(error, res);
  }
};

const loginAuthor = async (req, res) => {
  try {
    const { author_email, author_password } = req.body;
    const author = await Author.findOne({ author_email });
    if (!author) {

      return res.status(401).send({ message: "Email yoki parol noto'g'ri" });
    }

    const payload = {
      id: author._id,
      email: author.author_email,
      is_active: author.is_active,
      role: author.role,
    };

    const validPassword = bcrypt.compareSync(
      author_password,
      author.author_password
    );
    if (!validPassword) {
      console.log(validPassword);

      return res.status(401).send({ message: "Email yoki parol noto'g'ri" });
    }
    const tokens = authorJwt.generateTokens(payload);
    author.refresh_token = tokens.refreshToken
    await author.save()
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("refresh_token_ms")
    });


    res.status(200).send({ 
      message: "Tizimga hush kelibsiz",
      author_id : author._id, 
      accessToken : tokens.accessToken 
    });

    // try {
    //   setTimeout(function(){
    //     const err = new Error("unCaughException error")
    //     throw err 
    //   }, 1000)
    // } catch (error) {
    //   console.log(error);

    // }

    // new Promise((_, reject)=>{
    //   reject( new Error("unhandledRejection example"))
    // })


    // const token = jwt.sign(payload, config.get("tokenKey"), {
    //   expiresIn: config.get("tokenTime"),
    // });
  } catch (error) {
    errorHandler(error, res);
  }
};

const logoutAuthor = async (req, res) => {
  try {
    const { refreshToken } = req.cookies
    console.log(refreshToken);


    if (!refreshToken) {
      return res.status(400).send({ message: "Token topilmadi!" });
    }

    const author = await Author.findOneAndUpdate(
      { refresh_token: refreshToken },
      { refresh_token: "" },
      { new: true }
    );
    if (!author) {
      return res.status(400).send({ message: "Bunday token author yo'q" });
    }
    res.clearCookie("refreshToken");

    return res.status(200).send({ refreshToken: author.refresh_token });

  } catch (error) {
    errorHandler(error, res)
  }
}


const refreshAuthorToken = async (req, res) => {
  try {
    const { refreshToken } = req.cookies

    if (!refreshToken) {
      return res.status(400).send({ message: "Cookie token topilmadi!" });
    }
    const [error, tokenFromCookie] = await to(
      authorJwt.verifyRefreshToken(refreshToken)
    );
    if (error) {
      return res.status(401).send({ error: error.message })
    }
    const author = await Author.findOne({ refresh_token: refreshToken });
    if (!author) {

      return res.status(404).send({ message: "Author not found" })
    }

    const payload = {
      id: author._id,
      email: author.author_email,
      is_active: author.is_active,
    };

    const tokens = authorJwt.generateTokens(payload);
    author.refresh_token = tokens.refreshToken
    await author.save();

    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      maxAge: config.get("refresh_token_ms")
    });




    // const token = jwt.sign(payload, config.get("tokenKey"), {
    //   expiresIn: config.get("tokenTime"),
    // });
    res.status(200).send({ message: "Tizimga hush kelibsiz", accessToken: tokens.accessToken });

  } catch (error) {
    errorHandler(error, res)
  }
}


const deleteAuthorById = async (req, res) => {
  try {
    const id = req.params.id;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const author = await Author.deleteOne({ _id: id });

    if (!author.deletedCount) {
      return res
        .status(400)
        .send({ message: "Muallif topilmadi yoki o'chirilmagan" });
    }

    res.send({ message: "Muallif o'chirildi" });
  } catch (error) {
    errorHandler(error, res);
  }
};

const updateAuthor = async (req, res) => {
  try {
    const id = req.params.id;
    const {
      author_first_name,
      author_last_name,
      author_nick_name,
      author_email,
      author_phone,
      author_password,
      author_info,
      author_position,
      author_photo,
      is_expert,
    } = req.body;

    if (!mongoose.isValidObjectId(id)) {
      return res.status(400).send({ message: "Id noto'g'ri" });
    }

    const author = await Author.updateOne(
      { _id: id },
      {
        author_first_name,
        author_last_name,
        author_nick_name,
        author_email,
        author_phone,
        author_password,
        author_info,
        author_position,
        author_photo,
        is_expert,
      }
    );

    if (!author.nModified) {
      return res.status(400).send({ message: "Muallif yangilanmadi" });
    }

    res.send({ message: "Muallif yangilandi", id: newAuthor._id, newAuthor });
  } catch (error) {
    errorHandler(error, res);
  }
};

const activateAuthor = async (req, res) => {
  try {
    const link = req.params.link;
    const author = await Author.findOne({ activation_link: link });

    if (!author) {
      return res.status(400).send({ message: "Bunday avtor topilmadi" })
    }
    if (author.is_active) {
      return res.status(400).send({ message: "Avtor oldin faollashtirilgan" })
    }

    author.is_active = true;
    await author.save()

    res.send({
      message: "Avtor faollashtirildi",
      is_active: author.is_active
    })

  } catch (error) {

  }
}

module.exports = {
  getAuthors,
  getAuthorById,
  addAuthor,
  deleteAuthorById,
  updateAuthor,
  loginAuthor,
  logoutAuthor,
  refreshAuthorToken,
  activateAuthor
};
