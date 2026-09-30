// Deliberately insecure sample. The scanner reads this file and does not run it.

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

const app = express();
const JWT_SECRET = "super-secret-key";

app.use(cors({ origin: "*" }));

app.get("/users", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = '" + name + "'");
  db.findOne({ name: req.body.name });
});

app.post("/run", (req, res) => {
  exec("ls " + req.body.cmd, () => {});
});

app.get("/file", (req, res) => {
  const filePath = path.join("/var/data", req.query.file);
  fs.readFile(filePath, "utf8", (err, data) => {
    res.send(data);
  });
});

app.get("/proxy", async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});

app.get("/greet", (req, res) => {
  document.getElementById("title").innerHTML = req.query.name;
});

app.post("/profile", (req, res) => {
  Object.assign(user, req.body);
  user.save(req.body);
});

app.post("/login", (req, res) => {
  console.log("password", req.body.password);
  const token = jwt.sign({ id: req.body.id }, JWT_SECRET);
  res.cookie("token", token);
});

app.get("/next", (req, res) => {
  res.redirect(req.query.next);
});

app.post("/calc", (req, res) => {
  const result = eval(req.body.expr);
  res.send(String(result));
});
