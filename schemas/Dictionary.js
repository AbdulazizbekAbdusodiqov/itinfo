const { Schema, model } = require("mongoose");

const dictSchema = new Schema({
    term: {
        type: String,
        uppercase: true,
        required: true,
        trim: true,
        unique: true
    },
    letter: {
        type: String,
        uppercase: true
    },
});


module.exports = model("Dictionary", dictSchema)