require("dotenv").config()
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const db = require("better-sqlite3")("ourApp.db")
const marked = require("marked")
const sanitizeHTML = require("sanitize-html")
const cookieParser = require("cookie-parser")
const express = require('express')
db.pragma("journal_mode = WAL")

//Set up database
const createTables = db.transaction(() => {
	db.prepare(
		`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
	).run()

	db.prepare(
		`
		CREATE TABLE IF NOT EXISTS posts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title STRING NOT NULL,
			body TEXT NOT NULL,
			authorId INTEGER,
			createdDate TEXT,
			FOREIGN KEY (authorId) REFERENCES users(id)
		)
		`
	).run()
});

createTables()

//End Set up database

const app = express()

app.use(express.urlencoded({ extended: false }))


app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
	res.locals.errors = [];

	//Try to decode incoming cookie

	try {
		const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
		req.user = decoded
	} catch (err) {
		req.user = false;
	}

	res.locals.user = req.user;
	next()
})

app.use(function (req, res, next) {
	res.locals.filterUserHTML = function (content) {
		return sanitizeHTML(marked.parse(content), {
			allowedTags: ["p", "br", "ul", "ol", "li", "strong", "bold", "i", "em", "h1", "h2", "h3", "h4", "h5", "h6"],
			allowedAttributes: {}
		});
	};
	next();
});

app.get("/", (req, res) => {
	if (req.user) {
		const postsStatement = db.prepare("SELECT * FROM posts WHERE authorId = ? ORDER BY createdDate DESC")
		const posts = postsStatement.all(req.user.userid)
		posts.forEach(post => {
			console.log(post.id)
		})
		return res.render("dashboard.ejs", { posts } )
	}
	res.render("homepage.ejs")
})

function requireLogin(req, res, next) {
	if (req.user) {
		return next();
	}
	res.redirect("/login")
}

app.get("/login", (req, res) => {
	res.render("login.ejs")
})

app.get("/logout", (req, res) => {
	res.clearCookie("ourSimpleApp")
	res.redirect("/")
})

app.get("/create-post", requireLogin, (req, res) => {
	res.render("create-post.ejs");
})

function sharedPostValidation(req) {
	const errors = [];

	if (typeof req.body.title != "string") req.body.title = "";
	if (typeof req.body.body != "string") req.body.body = "";

	//trim and sanitize/strip html
	req.body.title = sanitizeHTML(req.body.title.trim(), { allowedTags: [], allowedAttributes: {} })
	req.body.body = sanitizeHTML(req.body.body.trim(), { allowedTags: [], allowedAttributes: {} })

	if (!req.body.title) errors.push("You must provide a title for your post.");
	if (!req.body.body) errors.push("You must provide content for your post.");

	return errors;
}

app.post("/create-post", requireLogin, (req, res) => {
	const errors = sharedPostValidation(req);

	if (errors.length) {
		return res.render("create-post.ejs", { errors });
	}

	//Saving post into database
	const statement = db.prepare("INSERT INTO posts (title, body, authorId, createdDate) VALUES (?, ?, ?, ?)");
	const result = statement.run(req.body.title, req.body.body, req.user.userid, new Date().toISOString());

	const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?");
	const realPost = getPostStatement.get(result.lastInsertRowid);

	res.redirect(`/post/${realPost.id}`)


})

app.post("/login", (req, res) => {
	let errors = [];

	if (typeof req.body.username !== "string") req.body.username = ""
	if (typeof req.body.password !== "string") req.body.password = ""

	if (req.body.username.trim() == "") errors = ["Invalid username/password"];
	if (req.body.password == "") errors = ["Invalid username/password"];

	if (errors.length) {
		return res.render("login.ejs", { errors });
	}

	const userLookupStatement = db.prepare("SELECT * FROM users WHERE username = ?")
	const maybeUser = userLookupStatement.get(req.body.username)

	if (!maybeUser) {
		errors = ["Invalid username/password"];
		return res.render("login", { errors });
	}

	const passwordMatch = bcrypt.compareSync(req.body.password, maybeUser.password)
	if (!passwordMatch) {

		errors = ["Invalid username/password"];
		return res.render("login", { errors });
	}

	if (passwordMatch) {
		//Log user in; give them a cookie

		const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: maybeUser.id, username: maybeUser.username }, process.env.JWTSECRET)

		res.cookie("ourSimpleApp", ourTokenValue, {
			httpOnly: true,
			secrue: true,
			sameSite: "strict",
			maxAge: 1000 * 60 * 60 * 24
		})

		res.redirect("/")
	}
})

app.get("/post/:id", (req, res) => {
	const statement = db.prepare(`SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorId = users.id WHERE posts.id = ?`);
	const post = statement.get(req.params.id);

	if (!post) {
		return res.redirect("/");
	}

	
	const isAuthor = post.authorId == req.user.userid;

	res.render("single-post.ejs", { post, isAuthor });

});

app.get("/edit-post/:id", requireLogin, (req, res) => {
	//Look up post
	const statement = db.prepare(`SELECT * FROM posts WHERE id = ?`);
	const post = statement.get(req.params.id);

	//If post !exist return to homepage || !author
	if (!post || post.authorId != req.user.userid) {
		return res.redirect("/");
	}

	//Else show edit page
	res.render("edit-post.ejs", { post });
})

app.post("/edit-post/:id", requireLogin, (req, res) => {
	//Look up post
	const statement = db.prepare(`SELECT * FROM posts WHERE id = ?`);
	const post = statement.get(req.params.id);
	console.log("Arrived at edit-post ID:" + req.params.id)

	//If post !exist return to homepage || !author
	if (!post || post.authorId != req.user.userid) {
		return res.redirect("/");
	}
	
	//Sanatizes Post
	const errors = sharedPostValidation(req);

	if (errors.length) {
		return res.render("edit-post.ejs", { errors, post });
	}


	const updateStatement = db.prepare("UPDATE posts SET title = ?, body = ? WHERE id = ?")
	updateStatement.run(req.body.title, req.body.body, req.params.id)
	res.redirect(`/post/${req.params.id}`)

})

app.post("/delete-post/:id", requireLogin, (req, res) => {
	//Look up post
	const statement = db.prepare(`SELECT * FROM posts WHERE id = ?`);
	const post = statement.get(req.params.id);

	//If post !exist return to homepage
	if (!post) {
		return res.redirect("/");
	}

	//If !author return to homepage
	if (post.authorId != req.user.userid) {
			return res.redirect("/");
	}

	const deleteStatement = db.prepare("DELETE FROM posts WHERE id = ?");
	deleteStatement.run(req.params.id);
	res.redirect("/");
});

app.post("/register", (req, res) => {
	var errors = [];

	if (typeof req.body.username !== "string") req.body.username = ""
	if (typeof req.body.password !== "string") req.body.password = ""

	req.body.username = req.body.username.trim();

	if (!req.body.username) errors.push("You must provide a username.");
	if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters long.");
	if (req.body.username && req.body.username.length > 10) errors.push("Username must be no more than 10 characters long.");
	if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters, numbers.");

	//Checking for duplicate username
	const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?");
	const usernameCheck = usernameStatement.get(req.body.username);
	if (usernameCheck) {
		errors.push("That username is already taken.");
	}

	if (!req.body.password) errors.push("You must provide a password.");
	if (req.body.password && req.body.password.length < 7) errors.push("Password must be at least 8 characters long.");
	if (req.body.password && req.body.password.length > 64) errors.push("password must be no more than 64 characters long.");

	if (errors.length) {
		return res.render("Homepage.ejs", { errors });
	}

	//Saving new user into database
	const salt = bcrypt.genSaltSync(10)
	req.body.password = bcrypt.hashSync(req.body.password, salt)

	const ourStatment = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
	const result = ourStatment.run(req.body.username, req.body.password)

	const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
	const ourUser = lookupStatement.get(result.lastInsertRowid)

	//Log user in; give them a cookie

	const ourTokenValue = jwt.sign({ exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username }, process.env.JWTSECRET)

	res.cookie("ourSimpleApp", ourTokenValue, {
		httpOnly: true,
		secrue: true,
		sameSite: "strict",
		maxAge: 1000 * 60 * 60 * 24
	})

	res.redirect("/")
})

app.listen(3000)