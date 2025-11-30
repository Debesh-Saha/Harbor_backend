"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.LinkModel = exports.ContentModel = exports.UserModel = void 0;
const mongoose_1 = __importStar(require("mongoose"));
mongoose_1.default.connect(process.env.MONGO_URI);
const UserSchema = new mongoose_1.Schema({
    username: { type: String },
    email: { type: String, unique: true, sparse: true },
    password: { type: String, required: false },
    googleId: { type: String, unique: true, sparse: true }
});
const ContentSchema = new mongoose_1.Schema({
    title: String,
    link: String,
    tags: [{ type: mongoose_1.default.Types.ObjectId, ref: 'Tag' }],
    type: String,
    userId: [{ type: mongoose_1.default.Types.ObjectId, ref: 'user', required: true }]
});
const linkSchema = new mongoose_1.Schema({
    hash: String,
    userId: [{ type: mongoose_1.default.Types.ObjectId, ref: 'user', required: true, unique: true }]
});
exports.UserModel = (0, mongoose_1.model)("user", UserSchema);
exports.ContentModel = (0, mongoose_1.model)("content", ContentSchema);
exports.LinkModel = (0, mongoose_1.model)("links", linkSchema);
//# sourceMappingURL=db.js.map