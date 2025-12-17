import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import Stripe from "stripe";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const decodeKey = Buffer.from(process.env.FIREBASE_TOKEN_KEY, "base64");
const serviceAccount = JSON.parse(decodeKey);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});

app.use(cors());
app.use(express.json());

/* ================= GLOBAL COLLECTIONS ================= */
let usersCollection;
let contestCollection;
let participationCollection;
let submissionCollection;
let paymentCollection;

/* ================= VERIFY TOKEN ================= */
const verifyToken = async (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) return res.status(401).send({ message: "Unauthorized access" });

    const token = authorization.split(" ")[1];
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = { email: decoded.email };
        next();
    } catch {
        return res.status(401).send({ message: "Unauthorized access" });
    }
};

/* ================= ROLE MIDDLEWARE ================= */
const verifyAdmin = async (req, res, next) => {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== "admin") return res.status(403).send({ message: "Forbidden" });
    next();
};

const verifyCreator = async (req, res, next) => {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (user?.role !== "creator" && user?.role !== "admin") {
        return res.status(403).send({ message: "Forbidden" });
    }
    next();
};

app.get("/", (req, res) => {
    res.send("this app is running and create api");
});

/* ================= DB CONNECT ================= */
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.hle6tlh.mongodb.net/?appName=Cluster0`;

const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    await client.connect();

    const db = client.db(process.env.DB_USERNAME);
    usersCollection = db.collection("users");
    contestCollection = db.collection("contests");
    participationCollection = db.collection("participants");
    submissionCollection = db.collection("submissions");
    paymentCollection = db.collection("payments");

    // user reletive api
    app.post("/users", async (req, res) => {
        try {
            const user = req.body;
            const exitingUser = await usersCollection.findOne({ email: user.email });
            if (exitingUser) {
                return res.json({
                    success: true,
                    message: "User already exists",
                    user: exitingUser,
                    insertedId: null,
                });
            }

            const newUser = {
                name: user.name,
                email: user.email,
                photoURL: user.photoURL || "",
                role: "user",
                wins: 0,
                participationCount: 0,
                createdAt: new Date(),
            };
            const result = await usersCollection.insertOne(newUser);
            res.status(201).json({
                success: true,
                message: "User registered successfully.",
                user: { ...newUser, _id: result.insertedId },
                insertedId: result.insertedId,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "User registered failed.",
                error: error.message,
            });
        }
    });

    // user verify email

    app.get("/users/:email", verifyToken, async (req, res) => {
        try {
            const email = req.params.email;
            if (req.user.email !== email) {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden access",
                });
            }
            const user = await usersCollection.findOne({ email });
            if (!user) {
                return res.status(404).json({
                    success: false,
                    message: "User not found",
                });
            }
            res.json({
                success: true,
                user,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch user",
                error: error.message,
            });
        }
    });

    // update user profile

    app.patch("/users/:email", verifyToken, async (req, res) => {
        try {
            const email = req.params.email;

            if (req.user.email !== email) {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden access",
                });
            }

            const updates = req.body;
            const allowedUpdates = ["name", "photoURL"];
            const updateData = {};

            allowedUpdates.forEach((field) => {
                if (updates[field] !== undefined) {
                    updateData[field] = updates[field];
                }
            });

            updateData.updatedAt = new Date();

            const result = await usersCollection.updateOne({ email }, { $set: updateData });

            if (result.matchedCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found",
                });
            }

            res.json({
                success: true,
                message: "Profile updated successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Profile update failed",
                error: error.message,
            });
        }
    });

    //  Admin reletive api

    app.get("/admin/users", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const { page = 1, limit = 10 } = req.query;
            const skip = (parseInt(page) - 1) * parseInt(limit);

            const users = await usersCollection
                .find({})
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .toArray();

            const total = await usersCollection.countDocuments({});

            res.json({
                success: true,
                users,
                pagination: {
                    total,
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(total / parseInt(limit)),
                },
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch users",
                error: error.message,
            });
        }
    });

    app.patch("/admin/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;
            const { role } = req.body;

            if (!["user", "creator", "admin"].includes(role)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid role. Must be user, creator, or admin",
                });
            }

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid user ID",
                });
            }

            const result = await usersCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: { role, updatedAt: new Date() } }
            );

            if (result.matchedCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: "User not found",
                });
            }

            res.json({
                success: true,
                message: "User role updated successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Role update failed",
                error: error.message,
            });
        }
    });

    app.get("/admin/contest", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const { page = 1, limit = 10, status } = req.query;
            const query = status ? { status } : {};
            const skip = (parseInt(page) - 1) * parseInt(limit);

            const contests = await contestsCollection
                .find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .toArray();

            const total = await contestsCollection.countDocuments(query);

            res.json({
                success: true,
                contests,
                pagination: {
                    total,
                    page: parseInt(page),
                    limit: parseInt(limit),
                    totalPages: Math.ceil(total / parseInt(limit)),
                },
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch contests",
                error: error.message,
            });
        }
    });

    app.patch("/admin/contest/:id/approve", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const result = await contestsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        status: "confirmed",
                        approvedAt: new Date(),
                    },
                }
            );

            if (result.matchedCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            res.json({
                success: true,
                message: "Contest approved successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Contest approval failed",
                error: error.message,
            });
        }
    });

    app.patch("/admin/contest/:id/reject", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const result = await contestsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        status: "rejected",
                        rejectedAt: new Date(),
                    },
                }
            );

            if (result.matchedCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            res.json({
                success: true,
                message: "Contest rejected successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Contest rejection failed",
                error: error.message,
            });
        }
    });

    app.delete("/admin/contest/:id", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const result = await contestsCollection.updateOne(
                { _id: new ObjectId(id) },
                {
                    $set: {
                        status: "rejected",
                        rejectedAt: new Date(),
                    },
                }
            );

            if (result.matchedCount === 0) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            res.json({
                success: true,
                message: "Contest rejected successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Contest rejection failed",
                error: error.message,
            });
        }
    });

    /* ================= CONTEST ================= */
    app.get("/contest", async (req, res) => {
        const { type, search, page = 1, limit = 10, status } = req.query;
        const query = {};
        if (status) query.status = status;
        if (type && type !== "all") query.contestType = type;
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: "i" } },
                { description: { $regex: search, $options: "i" } },
            ];
        }

        const skip = (page - 1) * limit;
        const total = await contestCollection.countDocuments(query);
        const contest = await contestCollection.find(query).skip(skip).limit(+limit).toArray();

        res.send({ contest, total, page: +page, totalPages: Math.ceil(total / limit) });
    });

    app.get("/contest/popular", async (req, res) => {
        try {
            const contests = await contestCollection
                .find({ status: "confirmed" })
                .sort({ participantsCount: -1 })
                .limit(5)
                .toArray();

            res.json({
                success: true,
                contests,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch popular contests",
                error: error.message,
            });
        }
    });
    app.get("/contest/:id", async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const contest = await contestCollection.findOne({
                _id: new ObjectId(id),
            });

            if (!contest) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            res.json({
                success: true,
                contest,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch contest",
                error: error.message,
            });
        }
    });

    app.get("/contest/my/created", verifyToken, async (req, res) => {
        try {
            const contests = await contestCollection
                .find({ creatorEmail: req.user.email })
                .sort({ createdAt: -1 })
                .toArray();

            res.json({
                success: true,
                contests,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch creator contests",
                error: error.message,
            });
        }
    });

    app.post("/contest", verifyToken, async (req, res) => {
        const contest = {
            ...req.body,
            creatorEmail: req.user.email,
            status: "pending",
            participantsCount: 0,
            winner: null,
            createdAt: new Date(),
        };
        res.send(await contestCollection.insertOne(contest));
    });

    //contest creator only approve update

    app.put("/api/contests/:id", verifyToken, verifyCreator, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const contest = await contestCollection.findOne({
                _id: new ObjectId(id),
            });

            if (!contest) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            if (contest.creatorEmail !== req.user.email) {
                return res.status(403).json({
                    success: false,
                    message: "You can only update your own contests",
                });
            }

            if (contest.status !== "pending") {
                return res.status(400).json({
                    success: false,
                    message: "Cannot update approved or rejected contests",
                });
            }

            const updateData = req.body;
            const updatedContest = {
                name: updateData.name,
                image: updateData.image,
                description: updateData.description,
                price: parseFloat(updateData.price),
                prizeMoney: parseFloat(updateData.prizeMoney),
                taskInstruction: updateData.taskInstruction,
                contestType: updateData.contestType,
                deadline: new Date(updateData.deadline),
                updatedAt: new Date(),
            };

            const result = await contestCollection.updateOne({ _id: new ObjectId(id) }, { $set: updatedContest });

            res.json({
                success: true,
                message: "Contest updated successfully",
                modifiedCount: result.modifiedCount,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Contest update failed",
                error: error.message,
            });
        }
    });

    app.delete("/contest/:id", verifyToken, verifyCreator, async (req, res) => {
        const contest = await contestCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (contest.creatorEmail !== req.user.email) {
            return res.status(403).send({ message: "Forbidden" });
        }
        res.send(await contestCollection.deleteOne({ _id: new ObjectId(req.params.id) }));
    });

    //payment relative api

    app.post("/payment-checkout-session", verifyToken, async (req, res) => {
        const { contestId, amount } = req.body;

        const exists = await paymentCollection.findOne({
            contestId: new ObjectId(contestId),
            userEmail: req.user.email,
        });
        if (exists) return res.status(400).send({ message: "Already registered" });

        const contest = await contestCollection.findOne({ _id: new ObjectId(contestId) });

        const session = await stripe.checkout.sessions.create({
            mode: "payment",
            payment_method_types: ["card"],
            customer_email: req.user.email,
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        unit_amount: Math.round(amount * 100),
                        product_data: { name: contest.name, description: `Registration for ${contest.description}` },
                    },
                    quantity: 1,
                },
            ],
            metadata: { contestId },
            success_url: `${process.env.SITE_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${process.env.SITE_DOMAIN}/payment-cancelled`,
        });

        res.send({ url: session.url });
    });

    app.post("/payment/confirm", verifyToken, async (req, res) => {
        try {
            const { sessionId } = req.body;

            if (!sessionId) {
                return res.status(400).json({
                    success: false,
                    message: "Session ID is required",
                });
            }

            const session = await stripe.checkout.sessions.retrieve(sessionId);

            if (session.payment_status !== "paid") {
                return res.status(400).json({
                    success: false,
                    message: "Payment not completed",
                });
            }

            const alreadyPaid = await paymentCollection.findOne({
                transactionId: session.payment_intent,
            });

            if (alreadyPaid) {
                return res.json({
                    success: true,
                    message: "Payment already confirmed",
                    alreadyProcessed: true,
                });
            }

            const contestId = session.metadata.contestId;
            const userEmail = session.metadata.userEmail || session.customer_email;

            const user = await usersCollection.findOne({ email: userEmail });

            const paymentRecord = {
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
                userName: user?.name || "Unknown",
                userPhoto: user?.photoURL || "",
                amount: session.amount_total / 100,
                transactionId: session.payment_intent,
                status: "completed",
                paidAt: new Date(),
            };

            await paymentCollection.insertOne(paymentRecord);

            await contestCollection.updateOne({ _id: new ObjectId(contestId) }, { $inc: { participantsCount: 1 } });

            await usersCollection.updateOne({ email: userEmail }, { $inc: { participationCount: 1 } });

            await participationCollection.insertOne({
                contestId: contestId,
                contestObjectId: new ObjectId(contestId),
                userEmail: userEmail,
                userName: user?.name || "Unknown",
                userPhoto: user?.photoURL || "",
                registeredAt: new Date(),
            });

            res.json({
                success: true,
                message: "Payment confirmed successfully",
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Payment confirmation failed",
                error: error.message,
            });
        }
    });

    // check payments

    app.get("/payment/check/:contestId", verifyToken, async (req, res) => {
        try {
            const contestId = req.params.contestId;
            const userEmail = req.user.email;

            const payment = await paymentCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
            });

            res.json({
                success: true,
                isRegistered: !!payment,
                payment: payment || null,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to check registration",
                error: error.message,
            });
        }
    });

    //user payment contests

    app.get("/payment/user/:email", verifyToken, async (req, res) => {
        try {
            const email = req.params.email;

            if (req.user.email !== email) {
                return res.status(403).json({
                    success: false,
                    message: "Forbidden access",
                });
            }

            const payments = await paymentCollection.find({ userEmail: email }).sort({ paidAt: -1 }).toArray();

            // Get contest details for each payment
            const contestIds = payments.map((p) => p.contestId);
            const contests = await contestCollection.find({ _id: { $in: contestIds } }).toArray();

            // Merge payment and contest data
            const participatedContests = payments.map((payment) => {
                const contest = contests.find((c) => c._id.toString() === payment.contestId.toString());
                return {
                    ...payment,
                    contest,
                };
            });

            // Sort by upcoming deadline
            participatedContests.sort((a, b) => {
                if (!a.contest || !b.contest) return 0;
                const dateA = new Date(a.contest.deadline);
                const dateB = new Date(b.contest.deadline);
                return dateA - dateB;
            });

            res.json({
                success: true,
                participatedContests,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch participated contests",
                error: error.message,
            });
        }
    });

    //participants for contest

    app.post("/participants", verifyToken, async (req, res) => {
        try {
            const { contestId } = req.body;
            const userEmail = req.user.email;

            const payment = await paymentCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
            });

            if (!payment) {
                return res.status(403).json({
                    success: false,
                    message: "Payment required to register as participant",
                });
            }

            const existingParticipant = await participationCollection.findOne({
                contestId: contestId,
                userEmail: userEmail,
            });

            if (existingParticipant) {
                return res.status(400).json({
                    success: false,
                    message: "Already registered as participant",
                });
            }

            const user = await usersCollection.findOne({ email: userEmail });

            const participant = {
                contestId: contestId,
                contestObjectId: new ObjectId(contestId),
                userEmail: userEmail,
                userName: user?.name || "Unknown",
                userPhoto: user?.photoURL || "",
                registeredAt: new Date(),
            };

            const result = await participationCollection.insertOne(participant);

            res.status(201).json({
                success: true,
                message: "Participant registered successfully",
                participantId: result.insertedId,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Participant registration failed",
                error: error.message,
            });
        }
    });

    app.get("/participants/:contestId", async (req, res) => {
        try {
            const contestId = req.params.contestId;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const participants = await participationCollection
                .find({ contestId: contestId })
                .sort({ registeredAt: -1 })
                .toArray();

            res.json({
                success: true,
                participants,
                count: participants.length,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch participants",
                error: error.message,
            });
        }
    });

    // submissions all relative api

    app.post("/submissions", verifyToken, async (req, res) => {
        try {
            const { contestId, submittedTask } = req.body;
            const userEmail = req.user.email;

            if (!contestId || !submittedTask) {
                return res.status(400).json({
                    success: false,
                    message: "Contest ID and submitted task are required",
                });
            }

            const payment = await paymentsCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
            });

            if (!payment) {
                return res.status(403).json({
                    success: false,
                    message: "Payment required before submitting task",
                });
            }

            const user = await usersCollection.findOne({ email: userEmail });

            const existingSubmission = await submissionCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
            });

            if (existingSubmission) {
                const result = await submissionCollection.updateOne(
                    { contestId: new ObjectId(contestId), userEmail: userEmail },
                    {
                        $set: {
                            submittedTask,
                            updatedAt: new Date(),
                        },
                    }
                );

                return res.json({
                    success: true,
                    message: "Task updated successfully",
                    modifiedCount: result.modifiedCount,
                });
            }

            const submission = {
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
                userName: user?.name || "Unknown",
                userPhoto: user?.photoURL || "",
                submittedTask: submittedTask,
                isWinner: false,
                submittedAt: new Date(),
            };

            const result = await submissionCollection.insertOne(submission);

            res.status(201).json({
                success: true,
                message: "Task submitted successfully",
                submissionId: result.insertedId,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Task submission failed",
                error: error.message,
            });
        }
    });

    app.get("/submissions/contest/:contestId", verifyToken, verifyCreator, async (req, res) => {
        try {
            const contestId = req.params.contestId;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const contest = await contestCollection.findOne({
                _id: new ObjectId(contestId),
            });

            if (!contest) {
                return res.status(404).json({
                    success: false,
                    message: "Contest not found",
                });
            }

            const user = await usersCollection.findOne({ email: req.user.email });

            if (contest.creatorEmail !== req.user.email && user.role !== "admin") {
                return res.status(403).json({
                    success: false,
                    message: "You can only view submissions for your own contests",
                });
            }

            const submissions = await submissionCollection
                .find({ contestId: new ObjectId(contestId) })
                .sort({ submittedAt: -1 })
                .toArray();

            res.json({
                success: true,
                submissions,
                count: submissions.length,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch submissions",
                error: error.message,
            });
        }
    });

    // submission for contest

    app.get("/submissions/user/:contestId", verifyToken, async (req, res) => {
        try {
            const contestId = req.params.contestId;
            const userEmail = req.user.email;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const submission = await submissionCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: userEmail,
            });

            res.json({
                success: true,
                submission: submission || null,
                hasSubmitted: !!submission,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch submission",
                error: error.message,
            });
        }
    });

    /* ================= WINNER ================= */
    app.patch("/contests/:id/winner", verifyToken, verifyCreator, async (req, res) => {
        const contest = await contestCollection.findOne({ _id: new ObjectId(req.params.id) });
        if (contest.creatorEmail !== req.user.email) {
            return res.status(403).send({ message: "Forbidden" });
        }

        await contestCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { winner: req.body } });

        await usersCollection.updateOne({ email: req.body.winnerEmail }, { $inc: { wins: 1 } });
        res.send({ success: true });
    });

    /* ================= LEADERBOARD ================= */
    app.get("/leaderboard", async (req, res) => {
        res.send(
            await usersCollection
                .find({ wins: { $gt: 0 } })
                .sort({ wins: -1 })
                .toArray()
        );
    });

    /* ================= STATS ================= */
    app.get("/stats/user", verifyToken, async (req, res) => {
        const participated = await paymentCollection.countDocuments({ userEmail: req.user.email });
        const won = await contestCollection.countDocuments({ "winner.email": req.user.email });

        res.send({
            participated,
            won,
            winPercentage: participated ? ((won / participated) * 100).toFixed(2) : 0,
        });
    });

    /* ================= CONTEST TYPES ================= */
    app.get("/contest-types", async (req, res) => {
        res.send(await contestCollection.distinct("contestType", { status: "confirmed" }));
    });
}

run();
app.listen(port, () => console.log(`Server running on port ${port}`));
