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

let usersCollection;
let contestCollection;
let participationCollection;
let submissionCollection;
let paymentCollection;

// token verify
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

// admin verify

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
                ...user,
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
            const result = await usersCollection.updateOne({ email }, { $set: updates });
            res.send(result);
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Profile update failed",
                error: error.message,
            });
        }
    });
    //  Admin reletive api

    app.get("/admin/users", verifyToken, async (req, res) => {
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

    app.patch("/admin/users/:id/role", verifyToken, async (req, res) => {
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
            const { page = 1, limit = 10, search = "", status } = req.query;

            const query = {};

            if (search) {
                query.$or = [
                    { name: { $regex: search, $options: "i" } },
                    { description: { $regex: search, $options: "i" } },
                ];
            }

            if (status && status !== "all") {
                query.status = status;
            }

            const skip = (page - 1) * limit;

            const contests = await contestCollection
                .find(query)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(Number(limit))
                .toArray();

            const total = await contestCollection.countDocuments(query);

            res.json({
                contests,
                pagination: {
                    total,
                    page: Number(page),
                    totalPages: Math.ceil(total / limit),
                },
            });
        } catch (error) {
            res.status(500).json({
                message: "Failed to load contests",
                error: error.message,
            });
        }
    });

    app.patch("/admin/contest/:id/approve", verifyToken, verifyAdmin, async (req, res) => {
        try {
            const contestId = req.params.id;
            const { winnerEmail } = req.body;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({ success: false, message: "Invalid contest ID" });
            }

            const contest = await contestCollection.findOne({
                _id: new ObjectId(contestId),
            });

            if (!contest) {
                return res.status(404).json({ success: false, message: "Contest not found" });
            }

            const updateData = {
                status: "confirmed",
                approvedAt: new Date(),
            };

            let winner = null;

            if (winnerEmail) {
                const submission = await submissionCollection.findOne({
                    contestId: new ObjectId(contestId),
                    userEmail: winnerEmail,
                });

                if (!submission) {
                    return res.status(400).json({
                        success: false,
                        message: "Winner must have a submission",
                    });
                }

                const winnerUser = await usersCollection.findOne({ email: winnerEmail });

                winner = {
                    email: winnerEmail,
                    name: winnerUser?.name || "Unknown",
                    photo: winnerUser?.photoURL || "",
                };

                updateData.winner = winner;
                updateData.winnerDeclaredAt = new Date();
                updateData.status = "completed";

                await submissionCollection.updateOne(
                    { contestId: new ObjectId(contestId), userEmail: winnerEmail },
                    { $set: { isWinner: true } }
                );

                await usersCollection.updateOne({ email: winnerEmail }, { $inc: { wins: 1 } });
            }

            await contestCollection.updateOne({ _id: new ObjectId(contestId) }, { $set: updateData });

            res.json({
                success: true,
                message: winner ? "Contest approved and winner declared" : "Contest approved successfully",
                winner,
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Contest approval failed",
                error: error.message,
            });
        }
    });

    app.patch("/admin/contest/:id/reject", verifyToken, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const result = await contestCollection.updateOne(
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

    app.delete("/admin/contest/:id", verifyToken, async (req, res) => {
        try {
            const id = req.params.id;

            if (!ObjectId.isValid(id)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid contest ID",
                });
            }

            const result = await contestCollection.updateOne(
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
    app.get("/admin/analytics", verifyToken, async (req, res) => {
        try {
            const totalContests = await contestCollection.countDocuments();
            const totalUsers = await usersCollection.countDocuments();
            const revenueResult = await paymentCollection
                .aggregate([{ $group: { _id: null, total: { $sum: "$amount" } } }])
                .toArray();
            const totalRevenue = revenueResult[0]?.total || 0;

            const recentContests = await contestCollection.find({}).sort({ createdAt: -1 }).limit(5).toArray();

            res.json({
                stats: {
                    totalContests,
                    totalUsers,
                    totalRevenue,
                    pendingCount: await contestCollection.countDocuments({ status: "pending" }),
                    totalParticipants: await paymentCollection.countDocuments(),
                },
                recentContests,
                newUsers: [],
                categories: [],
            });
        } catch (error) {
            res.status(500).json({ message: "Server error", error: error.message });
        }
    });

    // contest

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

    app.put("/contests/:id", verifyToken, async (req, res) => {
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

    app.delete("/contest/:id", verifyToken, async (req, res) => {
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
                return res.status(400).json({ success: false, message: "Session ID required" });
            }

            const session = await stripe.checkout.sessions.retrieve(sessionId);

            if (session.payment_status !== "paid") {
                return res.status(400).json({ success: false, message: "Payment not completed" });
            }

            const alreadyPaid = await paymentCollection.findOne({ transactionId: session.payment_intent });
            if (alreadyPaid) {
                return res.json({ success: true, message: "Payment already confirmed", alreadyProcessed: true });
            }

            const contestId = session.metadata.contestId;
            const userEmail = session.metadata.userEmail || session.customer_email;

            const user = await usersCollection.findOne({ email: userEmail });
            if (!user) return res.status(404).json({ success: false, message: "User not found" });

            const paymentRecord = {
                contestId: new ObjectId(contestId),
                userEmail,
                userName: user?.name || "Unknown",
                userPhoto: user?.photoURL || "",
                amount: session.amount_total / 100,
                transactionId: session.payment_intent,
                status: "completed",
                paidAt: new Date(),
            };

            await paymentCollection.insertOne(paymentRecord);

            await contestCollection.updateOne(
                { _id: new ObjectId(contestId) },
                {
                    $inc: { participantsCount: 1 },
                    $set: { status: "completed" },
                }
            );

            await usersCollection.updateOne({ email: userEmail }, { $inc: { participationCount: 1 } });

            try {
                await participationCollection.insertOne({
                    contestId,
                    contestObjectId: new ObjectId(contestId),
                    userEmail,
                    userName: user?.name || "Unknown",
                    userPhoto: user?.photoURL || "",
                    registeredAt: new Date(),
                });
            } catch (err) {
                if (err.code !== 11000) throw err;
            }

            res.json({ success: true, message: "Payment confirmed and participant registered successfully" });
        } catch (error) {
            res.status(500).json({ success: false, message: "Payment confirmation failed", error: error.message });
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

    app.get("/participants", verifyToken, async (req, res) => {
        const email = req.params.email;
        const payments = await paymentCollection.find({ userEmail: email }).toArray();

        const contestIds = payments.map((p) => new ObjectId(p.contestId));
        const contests = await contestCollection.find({ _id: { $in: contestIds } }).toArray();

        const contestsWithPayment = contests.map((contest) => {
            const payment = payments.find((p) => p.contestId === contest._id.toString());
            return { ...contest, paymentStatus: payment?.status };
        });

        contestsWithPayment.sort((a, b) => new Date(a.deadline) - new Date(b.deadline));

        res.send(contestsWithPayment);
    });

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

    app.get("/participants/:email", async (req, res) => {
        const { email } = req.params;
        try {
            const participations = await participationCollection
                .find({ userEmail: email })
                .sort({ registeredAt: -1 })
                .toArray();

            const uniqueContests = [];
            const contestIds = new Set();

            participations.forEach((p) => {
                if (!contestIds.has(p.contestId)) {
                    contestIds.add(p.contestId);
                    uniqueContests.push(p);
                }
            });

            res.json({ success: true, data: uniqueContests });
        } catch (err) {
            console.error(err);
            res.status(500).json({ success: false, message: "Server error" });
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

            const payment = await paymentCollection.findOne({
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

    app.get("/submissions/contest/:contestId", verifyToken, async (req, res) => {
        try {
            const contestId = req.params.contestId;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({ success: false, message: "Invalid contest ID" });
            }

            const contest = await contestCollection.findOne({ _id: new ObjectId(contestId) });
            if (!contest) {
                return res.status(404).json({ success: false, message: "Contest not found" });
            }
            const submissions = await submissionCollection
                .find({ contestId: new ObjectId(contestId) })
                .sort({ submittedAt: -1 })
                .toArray();

            res.json({ success: true, submissions, count: submissions.length });
        } catch (error) {
            res.status(500).json({ success: false, message: "Server error" });
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

    // winner relative api

    app.patch("/contests/:id/winner", verifyToken, async (req, res) => {
        try {
            const contestId = req.params.id;
            const { winnerEmail } = req.body;

            if (!ObjectId.isValid(contestId)) {
                return res.status(400).json({ message: "Invalid contest ID" });
            }

            const contest = await contestCollection.findOne({ _id: new ObjectId(contestId) });

            if (!contest) return res.status(404).json({ message: "Contest not found" });

            if (contest.creatorEmail !== req.user.email) {
                return res.status(403).json({ message: "Only creator can declare winner" });
            }

            if (contest.winner) {
                return res.status(400).json({ message: "Winner already declared" });
            }

            if (new Date() < new Date(contest.deadline)) {
                return res.status(400).json({ message: "Contest still running" });
            }

            const submission = await submissionCollection.findOne({
                contestId: new ObjectId(contestId),
                userEmail: winnerEmail,
            });

            if (!submission) {
                return res.status(400).json({ message: "Winner must submit a task" });
            }

            const winnerUser = await usersCollection.findOne({ email: winnerEmail });

            const winner = {
                email: winnerEmail,
                name: winnerUser?.name || "Unknown",
                photo: winnerUser?.photoURL || "",
            };

            await contestCollection.updateOne(
                { _id: new ObjectId(contestId) },
                {
                    $set: {
                        winner,
                        winnerDeclaredAt: new Date(),
                        status: "completed",
                    },
                }
            );

            await submissionCollection.updateOne(
                { contestId: new ObjectId(contestId), userEmail: winnerEmail },
                { $set: { isWinner: true } }
            );

            await usersCollection.updateOne({ email: winnerEmail }, { $inc: { wins: 1 } });

            res.json({ success: true, message: "Winner declared successfully" });
        } catch (err) {
            res.status(500).json({ message: "Winner declare failed", error: err.message });
        }
    });

    // winning by user

    app.get("/winning/user/me", verifyToken, async (req, res) => {
        try {
            const userEmail = req.user.email;

            const winningContests = await contestCollection
                .find({
                    $or: [{ "winner.email": userEmail }, { winner: userEmail }],
                    status: "completed",
                })
                .sort({ winnerDeclaredAt: -1 })
                .toArray();

            const cleanedContests = winningContests.map((contest) => ({
                ...contest,
                prizeMoney: contest.prizeMoney || contest.prize || contest.entryFee || 0,
            }));

            res.json({
                success: true,
                winningContests: cleanedContests,
                count: cleanedContests.length,
            });
        } catch (error) {
            console.error("My winnings error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch your winnings",
                error: error.message,
            });
        }
    });

    // leaderboard relative api added
    app.get("/leaderboard", async (req, res) => {
        try {
            const { limit = 20, page = 1 } = req.query; // ← ADD THIS LINE
            const limitNum = parseInt(limit) || 20;
            const skip = (parseInt(page) - 1) * limitNum;

            const topUsers = await usersCollection
                .find({ wins: { $gt: 0 } })
                .sort({ wins: -1, name: 1 })
                .skip(skip)
                .limit(limitNum)
                .project({ name: 1, photoURL: 1, wins: 1, email: 1, participationCount: 1 })
                .toArray();

            const total = await usersCollection.countDocuments({ wins: { $gt: 0 } });

            const leaderboard = topUsers.map((user, index) => ({
                ...user,
                rank: skip + index + 1,
            }));

            res.json({
                success: true,
                leaderboard,
                pagination: {
                    total,
                    page: parseInt(page),
                    limit: limitNum,
                    totalPages: Math.ceil(total / limitNum),
                },
            });
        } catch (error) {
            console.error("Leaderboard error:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch leaderboard",
                error: error.message,
            });
        }
    });
    // stats relative api

    app.get("/stats/user:email", verifyToken, async (req, res) => {
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

            const participated = user.participationCount || 0;
            const won = user.wins || 0;
            const winPercentage = participated > 0 ? ((won / participated) * 100).toFixed(2) : 0;

            res.json({
                success: true,
                stats: {
                    participated,
                    won,
                    winPercentage: parseFloat(winPercentage),
                },
            });
        } catch (error) {
            res.status(500).json({
                success: false,
                message: "Failed to fetch user statistics",
                error: error.message,
            });
        }
    });

    // contest type api

    app.get("/contest-types", async (req, res) => {
        try {
            const result = await contestCollection
                .aggregate([
                    { $match: { status: "confirmed" } },
                    { $group: { _id: "$contestType" } },
                    { $project: { _id: 0, type: "$_id" } },
                ])
                .toArray();

            const types = result.map((item) => item.type).filter((type) => type && typeof type === "string");

            res.json({
                success: true,
                types,
            });
        } catch (error) {
            console.error("Error fetching contest types:", error);
            res.status(500).json({
                success: false,
                message: "Failed to fetch contest types",
                error: error.message,
            });
        }
    });
}

run();
app.listen(port, () => console.log(`Server running on port ${port}`));
