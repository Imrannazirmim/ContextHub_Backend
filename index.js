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
const decode = Buffer.from(process.env.FIREBASE_TOKEN_KEY, "base64");
const serviceAccount = JSON.parse(decode);
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
});
app.use(cors());
app.use(express.json());

//verify token

const verifyToken = async (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ message: "Unauthorized access" });
    }
    const token = authorization.split(" ")[1];
    try {
        const decode = await admin.auth().verifyIdToken(token);
        req.user = { email: decode.email };
        next();
    } catch (error) {
        return res.status(401).send({ message: "unauthorized access" });
    }
};

// Role Middleware
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
    try {
        await client.connect();

        const db = client.db(process.env.DB_USERNAME);
        const usersCollection = db.collection("users");
        const contestCollection = db.collection("contests");
        const participationCollection = db.collection("participation");
        const submissionCollection = db.collection("submissions");
        const paymentCollection = db.collection("winners");

        // contest relative api

        // Change this line in your server code
        app.get("/contest", async (req, res) => {
            try {
                const { type, search, page = 1, limit = 10, status } = req.query; // status optional
                const query = {};

                if (status) query.status = status;

                if (type && type !== "all") query.contestType = type;

                if (search) {
                    query.$or = [
                        { name: { $regex: search, $options: "i" } },
                        { description: { $regex: search, $options: "i" } },
                    ];
                }

                const skip = (parseInt(page) - 1) * parseInt(limit);
                const total = await contestCollection.countDocuments(query);
                const contest = await contestCollection.find(query).skip(skip).limit(parseInt(limit)).toArray();

                res.send({
                    contest,
                    total,
                    page: parseInt(page),
                    totalPages: Math.ceil(total / limit),
                });
            } catch (err) {
                res.status(500).send({ message: "Failed to fetch contests", error: err.message });
            }
        });

        // popular contest
        app.get("/contest/popular", async (req, res) => {
            try {
                const contests = await contestCollection
                    .find({ status: "approved" })
                    .sort({ participantsCount: -1 })
                    .limit(5)
                    .toArray();

                res.send(contests);
            } catch (err) {
                res.status(500).send({
                    message: "Failed to fetch popular contests",
                    error: err.message,
                });
            }
        });

        // my created contest api
        app.get("/contest/my/created", verifyToken, async (req, res) => {
            try {
                const contests = await contestCollection
                    .find({ creatorEmail: req.user.email })
                    .sort({ createdAt: -1 })
                    .toArray();
                res.send(contests);
            } catch (err) {
                res.status(500).send({ message: "Failed to fetch contests", error: err.message });
            }
        });

        app.get("/contest/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await contestCollection.findOne(query);
            res.send(result);
        });

        app.post("/contest", verifyToken, async (req, res) => {
            console.log("Request body:", req.body);
            console.log("User email:", req.user.email); // ← Now this works

            try {
                const contest = {
                    ...req.body,
                    creatorEmail: req.user.email, // ← Now this works
                    status: "pending",
                    participantsCount: 0,
                    winner: null,
                    createdAt: new Date(),
                };
                const result = await contestCollection.insertOne(contest);
                res.send(result);
            } catch (err) {
                res.status(500).send({ message: "Failed to create contest", error: err.message });
            }
        });

        app.delete("/contest/:id", async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await contestCollection.deleteOne(query);
            res.send(result);
        });

        // Update contest details (Edit)
        app.patch("/contest/:id", verifyToken, async (req, res) => {
            const { id } = req.params;
            const { name, contestType, deadline, description } = req.body;

            if (!name && !contestType && !deadline && !description) {
                return res.status(400).send({ message: "No fields provided to update" });
            }

            try {
                // Only allow the creator or admin to update
                const contest = await contestCollection.findOne({ _id: new ObjectId(id) });

                if (!contest) {
                    return res.status(404).send({ message: "Contest not found" });
                }

                if (contest.creatorEmail !== req.user.email) {
                    return res.status(403).send({ message: "Forbidden: Not your contest" });
                }

                const updateFields = {};
                if (name) updateFields.name = name;
                if (contestType) updateFields.contestType = contestType;
                if (deadline) updateFields.deadline = new Date(deadline);
                if (description) updateFields.description = description;

                const result = await contestCollection.updateOne({ _id: new ObjectId(id) }, { $set: updateFields });

                res.send(result);
            } catch (err) {
                res.status(500).send({ message: "Failed to update contest", error: err.message });
            }
        });

        //payment relative api

        app.post("/payment-checkout-session", verifyToken, async (req, res) => {
            try {
                const { contestId, amount } = req.body;

                const contest = await contestCollection.findOne({
                    _id: new ObjectId(contestId),
                });

                if (!contest) {
                    return res.status(404).send({ message: "Contest not found" });
                }

                const session = await stripe.checkout.sessions.create({
                    mode: "payment",
                    payment_method_types: ["card"],
                    customer_email: req.user.email,
                    line_items: [
                        {
                            price_data: {
                                currency: "usd",
                                unit_amount: amount * 100,
                                product_data: {
                                    name: contest.name,
                                },
                            },
                            quantity: 1,
                        },
                    ],
                    metadata: {
                        contestId,
                        userEmail: req.user.email,
                    },
                    success_url: `${process.env.SITE_DOMAIN}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
                    cancel_url: `${process.env.SITE_DOMAIN}/payment-cancelled`,
                });

                res.send({ url: session.url });
            } catch (err) {
                res.status(500).send({ message: err.message });
            }
        });

        app.post("/payment/confirm", verifyToken, async (req, res) => {
            try {
                const { sessionId } = req.body;

                const session = await stripe.checkout.sessions.retrieve(sessionId);

                if (session.payment_status !== "paid") {
                    return res.status(400).send({ message: "Payment not completed" });
                }

                const exists = await paymentCollection.findOne({
                    transactionId: session.payment_intent,
                });

                if (exists) {
                    return res.send({ message: "Already recorded" });
                }

                const contestId = session.metadata.contestId;

                await paymentCollection.insertOne({
                    contestId: new ObjectId(contestId),
                    userEmail: session.customer_email,
                    amount: session.amount_total / 100,
                    transactionId: session.payment_intent,
                    status: "completed",
                    paidAt: new Date(),
                });

                await contestCollection.updateOne({ _id: new ObjectId(contestId) }, { $inc: { participantsCount: 1 } });

                res.send({ success: true });
            } catch (err) {
                res.status(500).send({ message: err.message });
            }
        });

        // app.post("/payment/create-indent", verifyToken, async (req, res) => {
        //     try {
        //         const { amount } = req.body;
        //         const paymentInfo = await stripe.paymentIntents.create({
        //             amount: amount * 100,
        //             currency: "usd",
        //             payment_method_types: ["card"],
        //         });
        //         res.send({
        //             clientSecret: paymentInfo.client_secret,
        //         });
        //     } catch (err) {
        //         res.status(500).send({
        //             message: "Payment intent failed",
        //             error: err.message,
        //         });
        //     }
        // });

        // app.post("/payments", verifyToken, async (req, res) => {
        //     try {
        //         const { contestId, amount, transactionId } = req.body;

        //         // Check if already registered
        //         const existingPayment = await paymentCollection.findOne({
        //             contestId: new ObjectId(contestId),
        //             userEmail: req.user.email,
        //         });

        //         if (existingPayment) {
        //             return res.status(400).send({ message: "Already registered for this contest" });
        //         }

        //         const payment = {
        //             contestId: new ObjectId(contestId),
        //             userEmail: req.user.email,
        //             amount,
        //             transactionId,
        //             status: "completed",
        //             paidAt: new Date(),
        //         };

        //         const result = await paymentCollection.insertOne(payment);

        //         // Increment participants count
        //         await contestCollection.updateOne(
        //             { _id: new ObjectId(contestId) },
        //             { $inc: { participantsCount: 1 } }
        //         );

        //         res.send(result);
        //     } catch (err) {
        //         res.status(500).send({ message: "Payment failed", error: err.message });
        //     }
        // });

        //  // Get user's participated contests
        // app.get("/payments/my-contests", verifyToken, async (req, res) => {
        //     try {
        //         const payments = await paymentCollection
        //             .find({ userEmail: req.user.email })
        //             .sort({ paidAt: -1 })
        //             .toArray();

        //         const contestIds = payments.map(p => p.contestId);
        //         const contests = await contestCollection
        //             .find({ _id: { $in: contestIds } })
        //             .toArray();

        //         const result = payments.map(payment => {
        //             const contest = contests.find(c => c._id.toString() === payment.contestId.toString());
        //             return { ...payment, contest };
        //         });

        //         res.send(result);
        //     } catch (err) {
        //         res.status(500).send({ message: "Failed to fetch contests", error: err.message });
        //     }
        // });

        // // Check if user registered for contest
        // app.get("/payments/check/:contestId", verifyToken, async (req, res) => {
        //     try {
        //         const payment = await paymentCollection.findOne({
        //             contestId: new ObjectId(req.params.contestId),
        //             userEmail: req.user.email
        //         });
        //         res.send({ registered: !!payment });
        //     } catch (err) {
        //         res.status(500).send({ message: "Failed to check registration", error: err.message });
        //     }
        // });

        // // participant
        // app.post("/participants", verifyToken, async (req, res) => {
        //     try {
        //         console.log("📝 Participation request:", {
        //             body: req.body,
        //             user: req.user.email,
        //         });

        //         const { contestId, paymentId, amount } = req.body;

        //         // Validate required fields
        //         if (!contestId || !paymentId || !amount) {
        //             return res.status(400).send({
        //                 message: "Missing required fields",
        //                 received: { contestId, paymentId, amount },
        //             });
        //         }

        //         const queryId = { _id: new ObjectId(contestId) };
        //         const contest = await contestCollection.findOne(queryId);

        //         if (!contest) {
        //             return res.status(404).send({ message: "Contest not found" });
        //         }

        //         if (contest.status !== "approved") {
        //             return res.status(400).send({
        //                 message: "Contest not available",
        //                 contestStatus: contest.status,
        //             });
        //         }

        //         // Check if user already participated
        //         const existingParticipation = await participationCollection.findOne({
        //             userEmail: req.user.email,
        //             contestId: contestId,
        //         });

        //         if (existingParticipation) {
        //             return res.status(400).send({ message: "Already registered" });
        //         }

        //         const participation = {
        //             userEmail: req.user.email,
        //             contestId,
        //             paymentId,
        //             amount,
        //             paymentDate: new Date(),
        //         };

        //         await participationCollection.insertOne(participation);

        //         await contestCollection.updateOne(queryId, {
        //             $inc: { participantsCount: 1 },
        //         });

        //         await usersCollection.updateOne(
        //             { email: req.user.email },
        //             { $inc: { contestsParticipated: 1 } },
        //             { upsert: false }
        //         );

        //         const newParticipantCount = (contest.participantsCount || 0) + 1;

        //         console.log("✅ Participation successful:", {
        //             user: req.user.email,
        //             contest: contest.name,
        //             participantCount: newParticipantCount,
        //         });

        //         res.send({
        //             message: "Successfully Registered",
        //             participantsCount: newParticipantCount,
        //         });
        //     } catch (err) {
        //         console.error("❌ Participation error:", err);

        //         if (err.code === 11000) {
        //             return res.status(400).send({ message: "Already registered" });
        //         }

        //         res.status(500).send({
        //             message: "Registration failed",
        //             error: err.message,
        //         });
        //     }
        // });

        // app.get("/participants/check/:contestId", verifyToken, async (req, res) => {
        //     try {
        //         const { contestId } = req.params;
        //         const participants = await participationCollection.find({ contestId }).toArray();
        //         res.send({ participants });
        //     } catch (err) {
        //         res.status(500).send({ message: "Check failed", error: err.message });
        //     }
        // });
    } catch (err) {
        console.log(err);
    }
}

run();

app.listen(port, () => {
    console.log(`server is running on port ${port}`);
});
