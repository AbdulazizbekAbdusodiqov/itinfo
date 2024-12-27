const Admin = require("../schemas/Admin.schema");
const { adminValidation } = require("../validation/admin.validation");
const {adminJwt} = require("../services/jwt.service");
const { errorHandler } = require("../helpers/error_handler");
const bcrypt = require("bcrypt");
const config = require("config");
const { to } = require("../helpers/to_promise");


const addAdmin = async (req, res) => {

    try {

        const { error, value } = adminValidation(req.body)
        console.log(error, value)
        if (error) return res.status(400).send({ message: error.message });

        const {
            name,
            email,
            phone,
            password,
            is_active,
            is_creater,
        } = value;
        
        const admin = await Admin.findOne({email});

        if (admin) return res.status(400).send({ message: "Admin already exists..." })

        const hashedPassword = bcrypt.hashSync(password, 7)

        const newAdmin = await Admin.create({
            name,
            email,
            phone,
            password : hashedPassword,
            is_active,
            is_creater,
        });

        const payload = {
            _id: newAdmin._id,
            email,
            role : 'admin'
        };

        const tokens = adminJwt.generateTokens(payload)

        newAdmin.token = tokens.refreshToken;

        await newAdmin.save();

        res.cookie("refreshToken", tokens.refreshToken, {
            httpOnly: true,
            maxAge: config.get("refresh_time_ms")
        });

        res.send({
            message: "Admin add successfully......",
            id: newAdmin._id,
            accessToken: tokens.accessToken
        })

    } catch (error) {

        errorHandler(error, res);

    }
};
const loginAdmin = async (req, res) => {
    
    try {
        const { email, password } = req.body;
        const admin = await Admin.findOne({ email });
        if (!admin) {
            return res.status(401).send({ msg: "Email yoki parol xato" });
        }
        const validPassword = bcrypt.compareSync(password, admin.password);
        if (!validPassword) {
            return res.status(401).send({ msg: "Email yoki parol xato" });
        }
        const payload = {
            id: admin._id,
            email: admin.email,
            is_active: admin.is_active,
            role : 'admin'
        };
        console.log(payload); 
        
        const {refreshToken} = adminJwt.generateTokens(payload);
        console.log(refreshToken);
        console.log("123");
        //refreshToken
        admin.refresh_token = refreshToken;
        await admin.save();
        res.cookie("refreshToken", refreshToken, {
            hhtpOnly: config.get("refresh_token_ms"),
        });

        res.status(200).send({ message: "tizimga hush kelibsiz", refreshToken: admin.refresh_token });
    } catch (error) {
        errorHandler(error, res);
    }
};

const logoutAdmin = async (req, res) => {
    try {

        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.status(404).send({ message: "Not found token" })
        }
        const admin = await Admin.findOneAndUpdate(
            { refresh_token: refreshToken },
            { refresh_token: "" },
            { new: true }
        );

        if (!admin) {
            return res.status(404).send({ message: "Author didn't exists" })
        }

        res.clearCookie("refreshToken");

        res.status(200).send({ message: "succes", refreshToken: admin.refresh_token });

    } catch (error) {
        errorHandler(error, res);
    }
};

const refreshAdminToken = async (req, res) => {
    try {
        const { refreshToken } = req.cookies;

        if (!refreshToken) {
            return res.status(404).send({ message: "AdminToken not found token" })
        }

        const [error, tokenFromCookie] = await to(adminJwt.verifyRefreshToken(refreshToken))

        if (error) {
            return res.status(401).send({ error: error.message })
        }

        const admin = await Admin.findOne({ refresh_token: refreshToken })

        if (!admin) {
            return res.status(404).send({ message: "Admin not found" })
        }

        const payload = {
            id: admin._id,
            email: admin.email,
            is_active: admin.is_active,
        };

        const tokens = adminJwt.generateTokens(payload);
        console.log(tokens);

        admin.refresh_token = tokens.refreshToken;
        await admin.save();

        res.cookie("refreshToken", tokens.refreshToken, {
            hhtpOnly: config.get("refresh_token_ms"),
        });

        res.status(200).send({ message: "Tizimga hush kelibsiz", refreshToken: admin.refresh_token });

    } catch (error) {
        errorHandler(error, res)
    }
};

const getAllAdmin = async (req, res) => {
    try {
        const found = await Admin.find();
        if (!found) {
            return res.status(404).send({ message: "not found" })
        }
        res.status(200).send({ message: "succes", found });
    } catch (error) {
        errorHandler(error, res);
    }
};

const getById = async (req, res) => {
    try {
        const { id } = req.params.id;
        const found = await Admin.findById({ id });
        if (!found) {
            return res.status(404).send({ message: "not found" })

        }
        res.status(200).send({ message: "succes", found });
    } catch (error) {
        errorHandler(error, res);
    }
};

const updateById = async (req, res) => {
    try {
        const id = req.params.id;
        const data = req.body;
        const update = await Admin.findByIdAndUpdate(id, data, { new: true });
        if (!update) {
            return res.status(404).send({ error: "not found" });
        }
        res.status(201).send({ message: "muvaffaqqiyatli yangilandi", update });
    } catch (error) {
        errorHandler(error, res);
    }
};

const deleteById = async (req, res) => {
    try {
        const id = req.params.id;
        const deleted = await Admin.findByIdAndDelete(id);
        if (!deleted) {
            return res.status(404).send({ error: "not found" });
        }
        res.status(201).send({ message: "muvaffaqqiyatli o'chirildi", deleted });
    } catch (error) {
        errorHandler(error, res);
    }
};

module.exports = {
    addAdmin,
    getById,
    updateById,
    deleteById,
    getAllAdmin,
    logoutAdmin,
    loginAdmin,
    refreshAdminToken
};
