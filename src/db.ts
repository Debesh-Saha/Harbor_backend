import mongoose, {model, Schema} from "mongoose";

mongoose.connect(process.env.MONGO_URI!);

const UserSchema = new Schema({
    username: { type: String },
    email: { type: String, unique: true, sparse: true },
    password: { type: String, required: false },
    googleId: { type: String, unique: true, sparse: true }
  });

const ContentSchema= new Schema({
    title: String,
    link: String, 
    tags: [{type: mongoose.Types.ObjectId, ref: 'Tag'}],
    type: String,
    userId: [{type: mongoose.Types.ObjectId, ref: 'user', required: true}]
});

const linkSchema= new Schema({
    hash: String,
    userId: [{type: mongoose.Types.ObjectId, ref: 'user', required: true, unique: true}]
})

export const UserModel= model("user", UserSchema);
export const ContentModel= model("content", ContentSchema);
export const LinkModel= model("links", linkSchema);