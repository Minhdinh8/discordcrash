/**
 * Discord Crash Game (split files) - index.js
 * - Discord.js v14 bot
 * - Express + Socket.IO for Web UI
 * - Provably-fair using HMAC-SHA512(serverSeed, clientSeed:sessionId)
 * - Per-user balances stored in data/users.json with deposit/withdraw endpoints
 * - Bets require sufficient balance; on bet placement balance is reserved (deducted).
 *
 * Usage:
 *  - Copy .env.example -> .env, fill BOT_TOKEN and SERVER_SEED, TRON_API_URL optional
 *  - npm install
 *  - node index.js
 *
 * Files expected/persisted in ./data:
 *  - games.json
 *  - users.json
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { Client, GatewayIntentBits, Partials, ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder, ModalBuilder, TextInputBuilder, TextInputStyle, InteractionType } = require('discord.js');
const axios = require('axios');
const crypto = require('crypto');
require('dotenv').config();

const BOT_TOKEN = process.env.BOT_TOKEN;
const SERVER_SEED = process.env.SERVER_SEED || 'PUBLIC_SERVER_SEED_EXAMPLE';
const TRON_API_URL = process.env.TRON_API_URL || 'https://api.trongrid.io/wallet/getnowblock';
const PORT = process.env.PORT || 3000;

if (!BOT_TOKEN) {
  console.error('Please set BOT_TOKEN in .env');
  process.exit(1);
}

// data folder & files
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const GAMES_FILE = path.join(DATA_DIR, 'games.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

function safeReadJson(filePath, defaultValue) {
  try {
    if (!fs.existsSync(filePath)) return defaultValue;
    const raw = fs.readFileSync(filePath, 'utf8') || '';
    return raw ? JSON.parse(raw) : defaultValue;
  } catch (e) {
    console.warn('Failed reading', filePath, e.message);
    return defaultValue;
  }
}

let gamesHistory = safeReadJson(GAMES_FILE, []);
let users = safeReadJson(USERS_FILE, {}); // { userId: { balance: number } }

function persistGames() {
  try { fs.writeFileSync(GAMES_FILE, JSON.stringify(gamesHistory, null, 2)); } catch (e) { console.error('Persist games failed', e); }
}
function persistUsers() {
  try { fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2)); } catch (e) { console.error('Persist users failed', e); }
}

// in-memory sessions
const sessions = new Map(); // sessionId -> session object

// Helper: fetch latest TRX block (clientSeed)
async function fetchBlock() {
  try {
    const res = await axios.get(TRON_API_URL, { timeout: 8000 });
    const data = res.data;
    // try various keys for block/hash
    const blockHash = data.blockID || data.block_id || data.hash || (data.block && (data.block.hash || data.block.blockID)) || JSON.stringify(data).slice(0, 64);
    return { raw: data, blockHash: String(blockHash) };
  } catch (err) {
    console.warn('Could not fetch TRX block:', err.message || err);
    // fallback pseudo
    const fallback = crypto.randomBytes(16).toString('hex');
    return { raw: null, blockHash: fallback };
  }
}

// Provably fair HMAC -> float [0,1)
function hmacFloat(serverSeed, clientSeed, extra = '') {
  const h = crypto.createHmac('sha512', serverSeed).update(`${clientSeed}:${extra}`).digest('hex');
  const slice = h.slice(0, 13); // 52 bits
  const num = parseInt(slice, 16);
  const denom = Math.pow(16, slice.length);
  const f = num / denom;
  return { hex: h, float: f };
}

// Map random float to crash multiplier
function floatToCrash(f) {
  const capped = Math.min(f, 0.999999999999);
  const crash = Math.max(1.0, Math.floor((1 / (1 - capped)) * 100) / 100);
  return Math.min(crash, 1000000);
}

// express + socket.io
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Utility: ensure user exists
function ensureUser(userId) {
  if (!users[userId]) {
    users[userId] = { balance: 0 };
    persistUsers();
  }
  return users[userId];
}

// API: Deposit (admin/web). Body: { userId, amount }
app.post('/api/deposit', (req, res) => {
  try {
    const { userId, amount } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const amt = Number(amount);
    if (!isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'invalid amount' });
    ensureUser(userId);
    users[userId].balance = Math.floor((users[userId].balance + amt) * 100) / 100;
    persistUsers();
    io.emit('balanceUpdate', { userId, balance: users[userId].balance });
    return res.json({ ok: true, userId, balance: users[userId].balance });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal' });
  }
});

// API: Withdraw (admin/web). Body: { userId, amount }
app.post('/api/withdraw', (req, res) => {
  try {
    const { userId, amount } = req.body;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    const amt = Number(amount);
    if (!isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'invalid amount' });
    ensureUser(userId);
    if (users[userId].balance < amt) return res.status(400).json({ error: 'insufficient balance' });
    users[userId].balance = Math.floor((users[userId].balance - amt) * 100) / 100;
    persistUsers();
    io.emit('balanceUpdate', { userId, balance: users[userId].balance });
    return res.json({ ok: true, userId, balance: users[userId].balance });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal' });
  }
});

// API: get balance
app.get('/api/balance/:userId', (req, res) => {
  const userId = req.params.userId;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  ensureUser(userId);
  return res.json({ userId, balance: users[userId].balance });
});

// API: create session
app.post('/api/create', async (req, res) => {
  try {
    const { guildId, channelId, creatorId, roundLength = 8000 } = req.body;
    if (!channelId) return res.status(400).json({ error: 'channelId required' });
    const block = await fetchBlock();
    const clientSeed = (block.blockHash || crypto.randomBytes(8).toString('hex')) + ':1';
    const id = crypto.randomBytes(6).toString('hex');
    const { hex, float } = hmacFloat(SERVER_SEED, clientSeed, id);
    const crash = floatToCrash(float);

    const session = {
      id, guildId, channelId, creatorId,
      clientSeed, clientBlockRaw: block.raw, serverSeed: SERVER_SEED,
      hmacHex: hex, hmacFloat: float, crashMultiplier: crash,
      status: 'waiting', createdAt: Date.now(), roundLength: Number(roundLength) || 8000,
      entries: {}, // userId -> { bet, cashedOutAt, payout, reserved }
      messageId: null, startTime: null, lastKnownMultiplier: 1.0
    };
    sessions.set(id, session);
    io.emit('sessionCreated', { id, crashPreview: crash, clientSeed: session.clientSeed });
    return res.json(session);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal' });
  }
});

// API: start session (web)
app.post('/api/start', async (req, res) => {
  try {
    const { sessionId } = req.body;
    const session = sessions.get(sessionId);
    if (!session) return res.status(404).json({ error: 'session not found' });
    if (session.status !== 'waiting') return res.status(400).json({ error: 'already started' });

    const channel = await client.channels.fetch(session.channelId).catch(() => null);
    if (!channel) return res.status(404).json({ error: 'discord channel not found' });

    const embed = createGameEmbed(session, 1.0, 'Starting soon — countdown');
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId(`bet:${session.id}`).setLabel('Bet').setStyle(ButtonStyle.Primary),
      new ButtonBuilder().setCustomId(`cashout:${session.id}`).setLabel('Cashout').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId(`verify:${session.id}`).setLabel('Verify').setStyle(ButtonStyle.Secondary)
    );
    const msg = await channel.send({ embeds: [embed], components: [row] });
    session.messageId = msg.id;
    session.status = 'countdown';
    // Start countdown
    startCountdown(session, msg);
    return res.json({ ok: true, sessionId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'internal' });
  }
});

function createGameEmbed(session, multiplier = 1.0, title = 'Crash — waiting') {
  return new EmbedBuilder()
    .setTitle(title)
    .setDescription(`Session ID: ${session.id}`)
    .addFields(
      { name: 'Multiplier', value: `${multiplier.toFixed(2)}x`, inline: true },
      { name: 'Status', value: `${session.status}`, inline: true },
      { name: 'Players', value: `${Object.keys(session.entries).length}`, inline: true }
    )
    .setFooter({ text: `Provably fair ready — serverSeed (public) available in web UI` })
    .setTimestamp();
}

async function startCountdown(session, message) {
  const countdownSeconds = 3;
  for (let s = countdownSeconds; s >= 1; s--) {
    session.status = 'countdown';
    const embed = createGameEmbed(session, 1.0, `Starting in ${s}...`);
    await message.edit({ embeds: [embed] }).catch(() => null);
    await new Promise(r => setTimeout(r, 1000));
  }
  runRound(session, message);
}

async function runRound(session, message) {
  session.status = 'running';
  session.startTime = Date.now();
  const startTime = session.startTime;
  const RL = session.roundLength || 8000;
  const crash = session.crashMultiplier;
  io.emit('roundStart', { sessionId: session.id, crash });

  let interval = null;
  const tickMs = 100;
  interval = setInterval(async () => {
    const elapsed = Date.now() - startTime;
    const t = Math.min(elapsed, RL);
    const multiplier = Math.pow(crash, t / RL);
    session.lastKnownMultiplier = multiplier;
    // update embed + clients
    const embed = createGameEmbed(session, multiplier, `Running`);
    await message.edit({ embeds: [embed] }).catch(() => null);
    io.emit('multiplier', { sessionId: session.id, multiplier });

    // if reached crash
    if (elapsed >= RL) {
      clearInterval(interval);
      session.status = 'crashed';
      finalizeRound(session, multiplier);
      const e2 = createGameEmbed(session, multiplier, `Crashed at ${multiplier.toFixed(2)}x`);
      await message.edit({ embeds: [e2] }).catch(() => null);

      // persist history
      gamesHistory.unshift({
        id: session.id, crashAt: multiplier, clientSeed: session.clientSeed,
        serverSeed: session.serverSeed, hmacHex: session.hmacHex, createdAt: session.createdAt, entries: session.entries
      });
      if (gamesHistory.length > 500) gamesHistory.pop();
      persistGames();
      io.emit('roundEnd', { sessionId: session.id, crashAt: multiplier });
      // mark finished
      session.finishedAt = Date.now();
    }
  }, tickMs);
}

function finalizeRound(session, crashMultiplier) {
  for (const [userId, entry] of Object.entries(session.entries)) {
    // if cashed out earlier, they already have payout computed and credited when cashed out
    if (entry.cashedOutAt) {
      // payout already credited on cashout
      continue;
    }
    // didn't cashout -> lost, reserved already deducted
    entry.payout = 0;
  }
  // nothing to return for lost bets
}

// Discord client
const client = new Client({ intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages], partials: [Partials.Channel] });

client.once('ready', () => {
  console.log('Bot ready:', client.user.tag);
});

// Interaction handlers: Buttons & Modals
client.on('interactionCreate', async (interaction) => {
  try {
    if (interaction.isButton()) {
      const [action, sessionId] = interaction.customId.split(':');
      const session = sessions.get(sessionId);
      if (!session) return interaction.reply({ content: 'Session not found', ephemeral: true });

      if (action === 'bet') {
        // show modal to enter bet amount (Discord user will be the bettor)
        const modal = new ModalBuilder().setCustomId(`betmodal:${sessionId}`).setTitle('Place your bet');
        const amountInput = new TextInputBuilder().setCustomId('amount').setLabel('Bet amount').setStyle(TextInputStyle.Short).setPlaceholder('Enter amount, e.g. 10').setRequired(true);
        modal.addComponents(new ActionRowBuilder().addComponents(amountInput));
        await interaction.showModal(modal).catch(err => console.error('showModal err', err));
        return;
      }

      if (action === 'cashout') {
        const userId = interaction.user.id;
        ensureUser(userId);
        const entry = session.entries[userId];
        if (!entry || !entry.bet) return interaction.reply({ content: 'You have no bet for this round.', ephemeral: true });
        if (entry.cashedOutAt) return interaction.reply({ content: `You already cashed out at ${entry.cashedOutAt}x`, ephemeral: true });

        // get current multiplier from session.lastKnownMultiplier
        const current = session.lastKnownMultiplier || 1.0;
        // record cashed out & compute payout
        entry.cashedOutAt = current;
        entry.payout = Math.floor(entry.bet * current * 100) / 100;
        // credit user balance
        users[userId] = users[userId] || { balance: 0 };
        users[userId].balance = Math.floor((users[userId].balance + entry.payout) * 100) / 100;
        persistUsers();
        io.emit('balanceUpdate', { userId, balance: users[userId].balance });

        await interaction.reply({ content: `Cashed out at ${current.toFixed(2)}x — payout ${entry.payout}`, ephemeral: true });
        return;
      }

      if (action === 'verify') {
        const embed = new EmbedBuilder()
          .setTitle('Provably Fair — Verify')
          .addFields(
            { name: 'Server seed (public)', value: String(session.serverSeed).slice(0, 200) },
            { name: 'Client seed', value: String(session.clientSeed).slice(0, 200) },
            { name: 'HMAC (sha512)', value: session.hmacHex.slice(0, 200) },
            { name: 'Expected crash', value: `${session.crashMultiplier}x` }
          );
        return interaction.reply({ embeds: [embed], ephemeral: true });
      }
    }

    // modal submit handler
    if (interaction.type === InteractionType.ModalSubmit) {
      if (interaction.customId.startsWith('betmodal:')) {
        const sessionId = interaction.customId.split(':')[1];
        const session = sessions.get(sessionId);
        if (!session) return interaction.reply({ content: 'Session not found', ephemeral: true });

        const amount = Number(interaction.fields.getTextInputValue('amount')) || 0;
        if (amount <= 0) return interaction.reply({ content: 'Invalid amount', ephemeral: true });

        const userId = interaction.user.id;
        ensureUser(userId);

        // check enough balance
        if (users[userId].balance < amount) return interaction.reply({ content: `Insufficient balance. Your balance: ${users[userId].balance}`, ephemeral: true });

        // Deduct immediately (reserve)
        users[userId].balance = Math.floor((users[userId].balance - amount) * 100) / 100;
        persistUsers();
        io.emit('balanceUpdate', { userId, balance: users[userId].balance });

        // record bet
        session.entries[userId] = session.entries[userId] || { bet: 0, cashedOutAt: null, payout: 0 };
        session.entries[userId].bet = Math.floor((session.entries[userId].bet + amount) * 100) / 100;
        // store reserved amount for clarity
        session.entries[userId].reserved = (session.entries[userId].reserved || 0) + amount;

        await interaction.reply({ content: `Bet accepted: ${amount}. Good luck!`, ephemeral: true });
        io.emit('playerBet', { sessionId: sessionId, userId, bet: amount });
      }
    }
  } catch (err) {
    console.error('interactionCreate err', err);
  }
});

// API: get history
app.get('/api/history', (req, res) => {
  res.json(gamesHistory);
});

// API: list sessions (simple)
app.get('/api/sessions', (req, res) => {
  const list = Array.from(sessions.values()).map(s => ({ id: s.id, status: s.status, crashPreview: s.crashMultiplier }));
  res.json(list);
});

// API: list users
app.get('/api/users', (req, res) => {
  res.json(users);
});

// Socket.io
io.on('connection', (socket) => {
  console.log('ws connected', socket.id);
  socket.on('getSessions', () => {
    const list = Array.from(sessions.values()).map(s => ({ id: s.id, status: s.status, crashPreview: s.crashMultiplier }));
    socket.emit('sessions', list);
  });
  socket.on('getUsers', () => {
    socket.emit('users', users);
  });
});

client.login(BOT_TOKEN).then(() => {
  server.listen(PORT, () => console.log('Server on', PORT));
}).catch(err => {
  console.error('Discord login failed', err);
  process.exit(1);
});
