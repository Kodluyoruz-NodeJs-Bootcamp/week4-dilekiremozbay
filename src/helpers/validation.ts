import Joi from "joi";

const registerSchema = Joi.object({
  username: Joi.string().min(4).max(25).required(),
  password: Joi.string().min(6).max(255).required(),
  firstName: Joi.string().min(3).max(25).required(),
  lastName: Joi.string().min(3).max(25).required(),
});

const loginSchema = Joi.object({
  username: Joi.string().min(4).max(25).required(),
  password: Joi.string().min(6).max(255).required(),
});

export default { registerSchema, loginSchema };
