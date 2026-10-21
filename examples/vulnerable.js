// Deliberately vulnerable regexes used for the redoscope demo.
const email = /^([a-zA-Z0-9]+[._-]?)+@example\.com$/;
const safe = /^[a-z]+@example\.com$/;
const dynamic = new RegExp("^(x+x+)+y$");
module.exports = { email, safe, dynamic };
