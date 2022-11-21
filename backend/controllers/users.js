/* eslint-disable consistent-return */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const { HttpStatusCode } = require('../utils/HttpStatusCode');
const { HTTP401Error } = require('../errors/HTTP401Error');
const { HTTP409Error } = require('../errors/HTTP409Error');
const { HTTP404Error } = require('../errors/HTTP404Error');
const BadRequestError = require('../errors/BadRequestError');

const { NODE_ENV, JWT_SECRET } = process.env;

module.exports.createUser = (req, res, next) => {
  const {
    name,
    about,
    avatar,
    email,
    password,
  } = req.body;

  bcrypt.hash(password, 10)
    .then((hash) => User.create({
      name,
      about,
      avatar,
      email,
      password: hash,
    }))
    .then((user) => {
      res.status(201).send({ data: user });
    })
    .catch((e) => {
      if (e.code === 11000) {
        return next(new HTTP409Error(`${req.body.email}Пользователь с таким email уже существует`));
      }
      if (e.name === 'ValidationError') {
        return next(new BadRequestError('Ошибка валидации'));
      }
      return next(e);
    });
};

module.exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find({});
    res.send({ users });
  } catch (error) {
    next(error);
  }
};

module.exports.getCurrentUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      next(new HTTP404Error(`Пользователь с id ${req.user._id} не найден`));
      return;
    }
    res.status(HttpStatusCode.OK).send(user);
  } catch (error) {
    next(error);
  }
};

module.exports.getUserById = async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (user === null) {
      next(new HTTP404Error(`Пользователь с id ${req.params.id} не найден`));
      return;
    }
    res.send({ data: user });
  } catch (error) {
    next(error);
  }
};

module.exports.updateUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      throw new HTTP404Error(`Пользователь с id ${req.params.id} не найден`);
    }
    const { name, about } = req.body;
    const newUser = await User.findByIdAndUpdate(
      req.user._id,
      { name, about },
      { new: true, runValidators: true },
    );
    res.send(newUser);
  } catch (e) {
    if (e.name === 'ValidationError' || e.name === 'CastError') {
      return next(new BadRequestError('Ошибка валидации. Переданные данные не корректны'));
    }
    return next(e);
  }
};

module.exports.updateAvatar = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);
    if (!user) {
      throw new HTTP404Error(`Пользователь с id ${req.params.id} не найден`);
    }
    const { avatar } = req.body;
    const newAvatar = await User.findByIdAndUpdate(
      req.user._id,
      { avatar },
      { new: true, runValidators: true },
    );

    res.send(newAvatar);
  } catch (e) {
    if (e.name === 'ValidationError' || e.name === 'CastError') {
      return next(new BadRequestError('Ошибка валидации. Переданные данные не корректны'));
    }
    return next(e);
  }
};

module.exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      next(new HTTP401Error('Неправильные почта или пароль'));
      return;
    }
    const matched = await bcrypt.compare(password, user.password);
    if (!matched) {
      next(new HTTP401Error('Неправильные почта или пароль'));
      return;
    }
    const token = jwt.sign({ _id: user._id }, NODE_ENV === 'production' ? JWT_SECRET : '🔐', { expiresIn: '7d' });
    res.status(HttpStatusCode.OK).cookie('jwt', token, {
      maxAge: 3600000 * 24 * 7,
      httpOnly: true,
      sameSite: true,
    }).send({ message: 'Этот токен безопасно сохранен в httpOnly куку' }).end();
  } catch (error) {
    next(error);
  }
};
