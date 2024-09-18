const express = require('express');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
});

const User = mongoose.model('User', userSchema);

const urlSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  originalUrl: String,
  shortenedUrl: String,
  date: { type: Date, default: Date.now },
});

const Url = mongoose.model('Url', urlSchema);

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.post('/signup', async (req, res) => {
  const { email, password, name } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ email, password: hashedPassword, name });
  await newUser.save();
  res.sendStatus(201);
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.sendStatus(401);
  }
});

app.post('/reset-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (user) {
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '15m' });
    const resetLink = `${process.env.FRONTEND_URL}/reset-password/${token}`;
    
    await transporter.sendMail({
      to: email,
      subject: 'Password Reset',
      text: `Click the link to reset your password: ${resetLink}`,
    });

    res.sendStatus(200);
  } else {
    res.sendStatus(404);
  }
});

app.post('/shorten-url', async (req, res) => {
  const { token, originalUrl } = req.body;
  const { userId } = jwt.verify(token, process.env.JWT_SECRET);
  const shortenedUrl = `short.url/${Math.random().toString(36).substr(2, 8)}`;
  const newUrl = new Url({ userId, originalUrl, shortenedUrl });
  await newUrl.save();
  res.json({ shortenedUrl });
});

app.get('/urls', async (req, res) => {
  const { token } = req.headers;
  const { userId } = jwt.verify(token, process.env.JWT_SECRET);
  const urls = await Url.find({ userId });
  res.json(urls);
});

app.get('/dashboard', async (req, res) => {
  const { token } = req.headers;
  const { userId } = jwt.verify(token, process.env.JWT_SECRET);
  const todayCount = await Url.countDocuments({ userId, date: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } });
  const monthCount = await Url.countDocuments({ userId, date: { $gte: new Date(new Date().setDate(1)) } });
  res.json({ todayCount, monthCount });
});

app.get('/:shortenedUrl', async (req, res) => {
  const { shortenedUrl } = req.params;
  const urlEntry = await Url.findOne({ shortenedUrl });

  if (urlEntry) {
    res.redirect(urlEntry.originalUrl);
  } else {
    res.sendStatus(404);
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
