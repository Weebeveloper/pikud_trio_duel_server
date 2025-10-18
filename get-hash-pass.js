const bcrypt = require("bcryptjs");

const pass = "";

bcrypt.hash(pass, 12).then((hash) => {
  console.log("Your hashed password:", hash);
});
