const path = require("node:path");
const { tests } = require("@iobroker/testing");

tests.integration(path.join(__dirname, ".."), {
    controllerVersion: "7.2.2",
});
