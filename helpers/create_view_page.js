const path = require('path')

const createViewPage = (page) => path.resolve(__dirname, "../views", `${page}.hbs`)

module.exports = {
    createViewPage,
}