"use strict";

const fs = require("node:fs");
const path = require("node:path");

// Reads `.env` from the project root into the environment.
//
// `process.loadEnvFile` is built into Node, so this is not a dependency — one
// fewer package in the path of an authentication decision.
//
// Two properties worth stating, because both are load-bearing:
//
//   * A variable already set in the environment wins over the file. That is
//     Node's own behaviour and it is the one deployment needs: a container or a
//     systemd unit passing DATABASE_URL must not be overridden by a `.env` that
//     was copied into the image by accident.
//
//   * Every entry point calls this before reading configuration. The service
//     used to read `.env` only in the database scripts, which meant `npm start`
//     silently ignored the file the README tells you to write.

const ROOT = path.resolve(__dirname, "..", "..");
const ENV_FILE = path.join(ROOT, ".env");

/**
 * @returns {boolean} whether a file was found and read. No file is the normal
 *   case — the service boots with no configuration at all.
 */
function loadDotEnv() {
  if (!fs.existsSync(ENV_FILE)) return false;
  try {
    process.loadEnvFile(ENV_FILE);
    return true;
  } catch (error) {
    // Loud, and fatal to the caller's own validation rather than here: a `.env`
    // that cannot be parsed means the process is about to run with configuration
    // the operator believes is applied. Guessing which half took effect is worse
    // than saying so.
    throw new Error(`.env could not be read: ${error?.message}`);
  }
}

module.exports = { ROOT, ENV_FILE, loadDotEnv };
