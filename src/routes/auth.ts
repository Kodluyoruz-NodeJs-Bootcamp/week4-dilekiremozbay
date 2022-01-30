import express from "express";

import authController from "../controllers/auth";

// Router initialisation
const router = express.Router();

// [POST] Login
router.post("/login", authController.login as any);

// [POST] Register
router.post("/register", authController.register as any);

// [POST] Token
router.post("/token", authController.token as any);

//[GET] me
router.get("/me", authController.authorizer as any, authController.me as any);

//[GET] users
router.get("/users", authController.findAllUsers as any);

export default router;
