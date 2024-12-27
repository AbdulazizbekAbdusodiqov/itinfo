async function to(promise) {
  return promise
    .then((response) => [null, response])
    .catch((error) => [error, null]);
}

module.exports = { to };
