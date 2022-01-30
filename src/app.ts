import "dotenv/config";
import path from "path";
import bodyParser from "body-parser";
import express from "express";
import { Request, Response } from "express";
import bearerToken from "express-bearer-token";
import expressLayouts from "express-ejs-layouts";
import session from "express-session";
import { createConnection } from "typeorm";

import { User } from "./entity/User";
import authRoutes from "./routes/auth";

const app = express();
const port = process.env.PORT;

Promise.all([
  // connect to mysql
  createConnection({
    name: "default",
    type: process.env.DB_TYPE as any,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    entities: [User],
    synchronize: true,
  }),
])
  .then(() => {
    console.log("Connected to MySQL");

    setupRoutes(app);

    app.listen(port, () => {
      console.log("API Listening to http://localhost:" + port);
    });
  })
  .catch((err) => {
    console.log("Application error", err);
  });

process.on("SIGINT", () => {
  process.exit(0);
});

function setupRoutes(app: express.Application) {
  app.use(bearerToken());
  app.use(express.static("public"));
  app.use(expressLayouts);
  app.set("layout", "./layout");
  app.set("view engine", "ejs");
  app.set("views", path.join(__dirname, "./views"));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));

  app.use(
    session({
      secret: "supersecret difficult to guess string",
      cookie: {},
      resave: false,
      saveUninitialized: false,
    })
  );

  app.post("/logout", (req, res) => {
    req.session.destroy((err) => {
      res.redirect("/");
    });
  });

  //Declare API category endpoints
  app.use("/", authRoutes);

  //login sayfasını render edildi
  app.get("/login", (req, res) => {
    res.render("login", { title: "About Page" });
  });

  //login sayfasını render edildi
  app.get("/register", (req, res) => {
    res.render("register", { title: "About Page" });
  });

  app.use(errorHandler as any);

  function errorHandler(
    err: Error,
    req: Request,
    res: Response,
    next: express.NextFunction
  ) {
    if (err.name === "UnauthorizedError") {
      return res.status(401).send({
        message: "Invalid token",
      });
    }

    return res.status(500).send({
      statusCode: 500,
      message: err.message,
    });
  }
}
