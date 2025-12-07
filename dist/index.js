"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const express_1 = __importDefault(require("express"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const zod_1 = require("zod");
const bcrypt_1 = __importDefault(require("bcrypt"));
const db_1 = require("./db");
const config_1 = require("./config");
const middleware_1 = require("./middleware");
const utils_1 = require("./utils");
const cors_1 = __importDefault(require("cors"));
const mongoose_1 = __importDefault(require("mongoose"));
const google_auth_library_1 = require("google-auth-library");
const client = new google_auth_library_1.OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((0, cors_1.default)({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
}));
app.post("/api/v1/google-auth", async (req, res) => {
    try {
        const { idToken } = req.body;
        if (!idToken)
            return res.status(400).json({ message: "ID Token missing" });
        const ticket = await client.verifyIdToken({
            idToken,
            ...(process.env.GOOGLE_CLIENT_ID ? { audience: process.env.GOOGLE_CLIENT_ID } : {})
        });
        const payload = ticket.getPayload();
        if (!payload)
            return res.status(403).json({ message: "Invalid Google token" });
        const googleId = payload.sub;
        const email = payload.email || null;
        const fullName = payload.name || "User";
        // Find by googleId first
        let user = await db_1.UserModel.findOne({ googleId });
        // If no googleId user -> check if this email was used before
        if (!user) {
            let existing = await db_1.UserModel.findOne({ email });
            if (existing) {
                existing.googleId = googleId;
                existing.username = existing.username || fullName;
                await existing.save();
                user = existing;
            }
            else {
                user = await db_1.UserModel.create({
                    username: fullName,
                    email,
                    googleId,
                    password: null
                });
            }
        }
        const token = jsonwebtoken_1.default.sign({ id: user._id }, config_1.JWT_SECRET);
        res.json({ message: "Google Authentication Successful", token });
    }
    catch (err) {
        console.error("GOOGLE AUTH ERROR:", err);
        res.status(500).json({ message: "Google Auth Failed" });
    }
});
app.post("/api/v1/signup", async (req, res) => {
    const requirebody = zod_1.z.object({
        username: zod_1.z.string().min(3, "username cannot be less than 3 characters").max(60, "Username must be less than 10 characters"),
        password: zod_1.z.string().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,20}$/, {
            message: "Password must contain 8-20 letters, atleast one uppercase, one lowercase, one number, one special character"
        })
    });
    const parseDataWithSuccess = requirebody.safeParse(req.body);
    if (!parseDataWithSuccess.success) {
        const errorMessages = parseDataWithSuccess.error.issues.map(issue => issue.message);
        res.status(411).json({
            message: "Incorrect format of credentials!",
            error: errorMessages,
        });
        return;
    }
    const username = req.body.username;
    const password = req.body.password;
    let errorthrown = false;
    try {
        const hashedpassword = await bcrypt_1.default.hash(password, 5);
        await db_1.UserModel.create({
            username: username,
            password: hashedpassword
        });
        res.json({
            message: "You are signed up!"
        });
    }
    catch (e) {
        res.status(403).json({
            message: "User already exits"
        });
    }
});
app.post("/api/v1/signin", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const response = await db_1.UserModel.findOne({
        username: username
    });
    if (!response) {
        res.json({
            message: "User is not present in the database"
        });
        return;
    }
    const passwordMatch = await bcrypt_1.default.compare(password, response.password);
    if (passwordMatch) {
        const token = jsonwebtoken_1.default.sign({
            id: response._id
        }, config_1.JWT_SECRET);
        res.json({
            message: "You are succesfully signed in!!",
            token: token
        });
    }
    else {
        res.status(403).json({
            message: "Incorrect Signin credential!! Signin Failed!!"
        });
    }
});
app.get("/api/v1/me", middleware_1.userMiddleware, async (req, res) => {
    try {
        const user = await db_1.UserModel.findById(req.userId).select("username email");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        res.json({
            username: user.username,
            email: user.email
        });
    }
    catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
});
app.post("/api/v1/content", middleware_1.userMiddleware, async (req, res) => {
    const link = req.body.link;
    const type = req.body.type;
    await db_1.ContentModel.create({
        link,
        type,
        title: req.body.title,
        userId: req.userId,
        tags: []
    });
    res.json({
        message: "Content added"
    });
});
app.get("/api/v1/content", middleware_1.userMiddleware, async (req, res) => {
    const userId = req.userId;
    const content = await db_1.ContentModel.find({
        userId: userId
    }).populate("userId", "username");
    res.json({
        content
    });
});
app.delete("/api/v1/content", middleware_1.userMiddleware, async (req, res) => {
    try {
        const contentId = req.query.contentId; // ← use query param, not body
        if (!contentId) {
            return res.status(400).json({ message: "contentId is required" });
        }
        if (!mongoose_1.default.Types.ObjectId.isValid(contentId)) {
            return res.status(400).json({ message: "Invalid contentId" });
        }
        if (!req.userId) {
            return res.status(401).json({ message: "Unauthorized" });
        }
        const result = await db_1.ContentModel.deleteOne({
            _id: contentId,
            userId: req.userId,
        });
        if (result.deletedCount === 0) {
            return res.status(404).json({ message: "No content found or not authorized" });
        }
        res.json({ message: "Deleted Content" });
    }
    catch (err) {
        console.error("Delete error:", err);
        res.status(500).json({ message: "Internal Server Error" });
    }
});
app.post("/api/v1/brain/share", middleware_1.userMiddleware, async (req, res) => {
    const share = req.body.share;
    if (share) {
        const existingLink = await db_1.LinkModel.findOne({
            userId: req.userId
        });
        if (existingLink) {
            res.json({
                hash: existingLink.hash
            });
            return;
        }
        const hash = (0, utils_1.random)(10);
        await db_1.LinkModel.create({
            userId: req.userId,
            hash: hash
        });
        res.json({
            hash
        });
    }
    else {
        await db_1.LinkModel.deleteOne({
            userId: req.userId
        });
        res.json({
            message: "Removed Link"
        });
    }
});
app.get("/api/v1/brain/:shareLink", async (req, res) => {
    const hash = req.params.shareLink;
    const link = await db_1.LinkModel.findOne({
        hash
    });
    if (!link) {
        res.status(411).json({
            message: "Sorry incorrect input"
        });
        return;
    }
    const content = await db_1.ContentModel.find({
        userId: link.userId
    });
    const user = await db_1.UserModel.findOne({
        _id: link.userId
    });
    if (!user) {
        res.status(411).json({
            message: "User not found, error should ideally not happen"
        });
        return;
    }
    res.json({
        username: user.username,
        content: content
    });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port", PORT);
});
//# sourceMappingURL=index.js.map