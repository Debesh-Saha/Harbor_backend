import mongoose from "mongoose";
export declare const UserModel: mongoose.Model<{
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
}, {}, {}, {}, mongoose.Document<unknown, {}, {
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
}, {}, mongoose.DefaultSchemaOptions> & {
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
} & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}, mongoose.Schema<any, mongoose.Model<any, any, any, any, any, any>, {}, {}, {}, {}, mongoose.DefaultSchemaOptions, {
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
}, mongoose.Document<unknown, {}, mongoose.FlatRecord<{
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
}>, {}, mongoose.ResolveSchemaOptions<mongoose.DefaultSchemaOptions>> & mongoose.FlatRecord<{
    username?: string | null;
    email?: string | null;
    password?: string | null;
    googleId?: string | null;
}> & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}>>;
export declare const ContentModel: mongoose.Model<{
    tags: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    type?: unknown;
    title?: unknown;
    link?: unknown;
}, {}, {}, {}, mongoose.Document<unknown, {}, {
    tags: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    type?: unknown;
    title?: unknown;
    link?: unknown;
}, {}, mongoose.DefaultSchemaOptions> & {
    tags: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    type?: unknown;
    title?: unknown;
    link?: unknown;
} & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}, mongoose.Schema<any, mongoose.Model<any, any, any, any, any, any>, {}, {}, {}, {}, mongoose.DefaultSchemaOptions, {
    tags: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    type?: string | null;
    title?: string | null;
    link?: string | null;
}, mongoose.Document<unknown, {}, mongoose.FlatRecord<{
    tags: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    type?: string | null;
    title?: string | null;
    link?: string | null;
}>, {}, mongoose.ResolveSchemaOptions<mongoose.DefaultSchemaOptions>> & mongoose.FlatRecord<{
    tags: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    type?: string | null;
    title?: string | null;
    link?: string | null;
}> & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}>>;
export declare const LinkModel: mongoose.Model<{
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    hash?: unknown;
}, {}, {}, {}, mongoose.Document<unknown, {}, {
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    hash?: unknown;
}, {}, mongoose.DefaultSchemaOptions> & {
    userId: mongoose.Types.DocumentArray<{
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }, mongoose.Types.Subdocument<mongoose.mongo.BSON.ObjectId, any, {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }> & {
        prototype?: unknown;
        cacheHexString?: unknown;
        generate?: any;
        createFromTime?: any;
        createFromHexString?: any;
        createFromBase64?: any;
        isValid?: any;
    }>;
    hash?: unknown;
} & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}, mongoose.Schema<any, mongoose.Model<any, any, any, any, any, any>, {}, {}, {}, {}, mongoose.DefaultSchemaOptions, {
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    hash?: string | null;
}, mongoose.Document<unknown, {}, mongoose.FlatRecord<{
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    hash?: string | null;
}>, {}, mongoose.ResolveSchemaOptions<mongoose.DefaultSchemaOptions>> & mongoose.FlatRecord<{
    userId: {
        prototype?: mongoose.Types.ObjectId | null;
        cacheHexString?: unknown;
        generate?: {} | null;
        createFromTime?: {} | null;
        createFromHexString?: {} | null;
        createFromBase64?: {} | null;
        isValid?: {} | null;
    }[];
    hash?: string | null;
}> & {
    _id: mongoose.Types.ObjectId;
} & {
    __v: number;
}>>;
//# sourceMappingURL=db.d.ts.map