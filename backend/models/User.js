const mongoose = require('mongoose');

const deviceSchema = new mongoose.Schema({
  credentialID: { type: Buffer, required: true },
  credentialPublicKey: { type: Buffer, required: true },
  counter: { type: Number, required: true, default: 0 },
  transports: { type: [String], default: [] },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  // WebAuthn User ID (needs to be stored as a string or buffer)
  internalId: { type: String, required: true, unique: true },
  devices: [deviceSchema],
  // Used to store the challenge temporarily during registration/login ceremonies
  currentChallenge: { type: String }
});

module.exports = mongoose.model('User', userSchema);
