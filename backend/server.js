require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const dns = require('dns');

// Force Node.js to use Google's/Cloudflare's DNS to prevent MongoDB Atlas SRV lookup failures
dns.setServers(['8.8.8.8', '1.1.1.1']);
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const User = require('./models/User');

const app = express();
app.use(express.json());
app.use(cors());

// Serve static frontend files
app.use(express.static(path.join(__dirname, '../frontend')));

const PORT = 3000;
const rpName = 'Fingerprint Auth App';
const rpID = 'localhost';
const origin = `http://${rpID}:${PORT}`;

// Connect to MongoDB
const MONGODB_URI = 'mongodb+srv://ritikmahakalkar16_db_user:9763767457@cluster0.p3hjwwa.mongodb.net/?appName=Cluster0';
mongoose.connect(MONGODB_URI)
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- REGISTRATION ---

app.post('/api/register/generate-options', async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  let user = await User.findOne({ username });
  if (!user) {
    // Create a new user if one doesn't exist
    const internalId = crypto.randomUUID();
    user = new User({ username, internalId, devices: [] });
    await user.save();
  }

  const userDevices = user.devices.map(dev => ({
    id: dev.credentialID,
    type: 'public-key',
    transports: dev.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: user.internalId,
    userName: user.username,
    timeout: 60000,
    attestationType: 'none',
    excludeCredentials: userDevices,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
      // To specifically ask for built-in authenticators (like fingerprint)
      authenticatorAttachment: 'platform',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Save the challenge temporarily to verify the response later
  user.currentChallenge = options.challenge;
  await user.save();

  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const { username, response } = req.body;
  const user = await User.findOne({ username });

  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'User not found or no registration in progress' });
  }

  const expectedChallenge = user.currentChallenge;

  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: response.response.transports || [],
      };

      user.devices.push(newDevice);
      user.currentChallenge = undefined; // Clear the challenge
      await user.save();

      return res.json({ verified: true });
    }

    return res.status(400).json({ error: 'Registration verification failed' });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

// --- AUTHENTICATION (LOGIN) ---

app.post('/api/login/generate-options', async (req, res) => {
  const { username } = req.body;
  const user = await User.findOne({ username });

  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const userDevices = user.devices.map(dev => ({
    id: dev.credentialID,
    type: 'public-key',
    transports: dev.transports,
  }));

  const options = await generateAuthenticationOptions({
    rpID,
    timeout: 60000,
    allowCredentials: userDevices,
    userVerification: 'preferred',
  });

  user.currentChallenge = options.challenge;
  await user.save();

  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const { username, response } = req.body;
  const user = await User.findOne({ username });

  if (!user || !user.currentChallenge) {
    return res.status(400).json({ error: 'User not found or no login in progress' });
  }

  const expectedChallenge = user.currentChallenge;

  // Find the specific device used for login
  const device = user.devices.find(
    dev => Buffer.from(dev.credentialID).toString('base64url') === response.id
  );

  if (!device) {
    return res.status(400).json({ error: 'Authenticator not registered for this user' });
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: device.credentialPublicKey,
        credentialID: device.credentialID,
        counter: device.counter,
      },
      requireUserVerification: true,
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update the counter
      device.counter = authenticationInfo.newCounter;
      user.currentChallenge = undefined;
      await user.save();

      return res.json({ verified: true, username: user.username });
    }

    return res.status(400).json({ error: 'Login verification failed' });
  } catch (error) {
    console.error(error);
    return res.status(400).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
