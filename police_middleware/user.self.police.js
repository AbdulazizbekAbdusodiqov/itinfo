module.exports = async function (req, res, next) {
    try {
        const id = req.params.id
        
        if (id !== req.user.id) {
            return res.status(403).send({ message: "Sizda bunday huquq yo'q" })
        }
        next();
    } catch (error) {
        console.log(error);
        return res.status(401).send({ message: error.message });
    }
};
