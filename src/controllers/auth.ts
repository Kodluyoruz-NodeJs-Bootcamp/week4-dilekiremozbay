import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import _ from "lodash";
import { v4 as uuidv4 } from "uuid";

import { User } from "../entity/User";
import validation from "../helpers/validation";

// Override session data type
declare module "express-session" {
  interface SessionData {
    browserDetails: {
      userAgent: undefined | string;
    };

    accessToken: undefined | string;
  }
}

// Override request data type
declare module "express" {
  interface Request {
    tokenData: {
      userId: string;
      browserDetails: {
        userAgent: string;
      };
    };
  }
}

const login = async (req: Request, res: Response) => {
  const { error } = validation.loginSchema.validate(req.body);

  if (error) {
    return res.status(400).json({
      status: 400,
      message: "INPUT_ERRORS",
      errors: error.details,
      original: error._original,
    });
  }

  const user = await User.findOne({ username: req.body.username });

  if (!user) {
    return res.status(401).json({ message: "incorrect username or password" });
  }

  // Check if the username is correct
  // Check if the password correct
  const validatePassword = await bcrypt.compare(
    req.body.password,
    user.password
  );

  if (!validatePassword) {
    return res.status(401).json({ message: "incorrect username or password" });
  }

  const browserDetails = { userAgent: req.headers["user-agent"] };

  // Generate Access & Refresh Token
  const accessToken = jwt.sign(
    {
      _id: user.id,
      browserDetails,
    },
    process.env.SECRET_ACCESS_TOKEN!,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
  const refreshToken = jwt.sign(
    {
      _id: user.id,
    },
    process.env.SECRET_REFRESH_TOKEN!,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );

  await addRefreshToken(user, refreshToken);

  //Tarayıcı bilgileri kaydedildi//
  req.session.browserDetails = browserDetails;

  res.redirect("/users");
};

const register = async (req: Request, res: Response) => {
  const { error } = validation.registerSchema.validate(req.body, {
    abortEarly: false,
  });

  if (error) {
    return res.status(400).json({
      status: 400,
      message: "INPUT_ERRORS",
      errors: error.details,
      original: error._original,
    });
  }

  // Encrypt password
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  const user = new User();

  user.username = req.body.username;
  user.firstName = req.body.firstName;
  user.lastName = req.body.lastName;
  user.password = hashedPassword;
  user.security = {
    tokens: [],
  };

  // Attempt to save the user in database
  await user.save();

  // Generate Access & Refresh Token
  const accessToken = jwt.sign(
    {
      _id: user.id,
      username: user.username,
    },
    process.env.SECRET_ACCESS_TOKEN!,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );
  const refreshToken = jwt.sign(
    {
      _id: user.id,
      username: user.username,
    },
    process.env.SECRET_REFRESH_TOKEN!,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  );

  // Assign the token to user and save
  await User.update(
    { username: user.username },
    {
      security: {
        tokens: [
          {
            refreshToken: refreshToken,
            createdAt: new Date(),
          },
        ],
      },
    }
  );

  res.redirect("/login");
};

const token = async (req: Request, res: Response) => {
  const refreshToken = req.body.refreshToken;

  // Verify if the token is valid - if not, don't authorise, ask to re-authenticate
  const decodeRefreshToken = jwt.verify(
    refreshToken,
    process.env.SECRET_REFRESH_TOKEN!
  ) as jwt.JwtPayload;
  const user = await User.findOne({
    username: decodeRefreshToken.sub!,
  });

  if (!user) {
    return res.status(401).json({ message: "Account deleted" });
  }

  const existingRefreshTokens = user.security.tokens;
  const refreshTokenExists = existingRefreshTokens.some(
    (token) => token.refreshToken === refreshToken
  );

  // Check if refresh token is in document
  if (!refreshTokenExists) {
    return res
      .status(401)
      .json({ error: { status: 401, message: "INVALID_REFRESH_TOKEN" } });
  }

  // Generate new Access Token
  const accessToken = jwt.sign(
    {
      _id: user.id,
    },
    process.env.SECRET_ACCESS_TOKEN!,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  );

  // Send new Access Token
  res.status(200).json({
    success: {
      status: 200,
      message: "ACCESS_TOKEN_GENERATED",
      accessToken: accessToken,
    },
  });
};

const addRefreshToken = async (user: User, refreshToken: string) => {
  let tokens = user.security.tokens.slice(0);

  tokens.push({
    _id: uuidv4(),
    refreshToken: refreshToken,
    createdAt: new Date(),
  });

  // store only the last 5 tokens
  tokens = tokens.slice(tokens.length - 5);

  await User.update(
    { username: user.username },
    {
      security: {
        tokens,
      },
    }
  );
};

function authorizer(req: Request, res: Response, next: NextFunction) {
  console.log("authorization token", req.token);

  jwt.verify(req.token!, process.env.SECRET_ACCESS_TOKEN! as any, cb as any);

  function cb(
    err: Error,
    decoded: { userId: string; browserDetails: { userAgent: string } }
  ) {
    console.log("verify result", { err, decoded, session: req.session });

    if (err) {
      return res.status(401).json({ message: err.message });
    }

    if (
      req.session.browserDetails?.userAgent !== decoded.browserDetails.userAgent
    ) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    req.tokenData = decoded;

    next();
  }
}

async function me(req: Request, res: Response) {
  const user = await User.findOne({ id: Number(req.tokenData.userId) });

  console.log("req.token", req.token);

  if (!user) {
    return res.status(401).json({ message: "Account deleted" });
  }

  res.json(cleanUserObject(user));
}

async function findAllUsers(req: Request, res: Response) {
  const users = await User.find({});
  const cleanedUsers = users.map(cleanUserObject);

  res.json(cleanedUsers);
}

function cleanUserObject(user: User) {
  return _.pick(user, ["_id", "username", "firstName", "lastName"]);
}

export default { login, register, token, me, authorizer, findAllUsers };
