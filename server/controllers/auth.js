"use strict";

import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/***REGISTER USER***/
/**
 * Asyc due to call on MongoDb
 * req = request from front-end
 * res = response from back-end
 * @param {*} req
 * @param {*} res
 */
export const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      picturePath,
      friends,
      location,
      occupation,
    } = req.body;
    const salt = await bcrypt.genSalt();

    //hashing password and using encryption
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: passwordHash,
      picturePath,
      friends,
      location,
      occupation,
      viewProfile: Math.floor(Math.random() * 1000),
      impressions: Math.floor(Math.random() * 1000),
    });
    const savedUser = await newUser.save();
    //sending correct status to user, making sure User is getting the correct response
    res.status(201).json(savedUser);
  } catch (err) {
    //sends wrong status to user with error message
    res.status(500).json({ error: err.message });
  }
};

/***LOGGING IN***/

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email: email });
    if (!user)
      return res
        .status(400)
        .json({ msg: "Invalid input: The user does not exist " });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "invalid credentials. " });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    delete user.password;
    res.status(200).json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};
