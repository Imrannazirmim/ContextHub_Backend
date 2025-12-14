import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import Stripe from "stripe";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import admin from "firebase-admin";

dotenv.config();
const app = express();
const port = process.env.PORT || 3000;
const stripe = new Stripe(process.env.STRIPE_PUBLIC_KEY);
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
  if (user?.role !== "admin")
    return res.status(403).send({ message: "Forbidden" });
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
    const usersCollection = await db.collection("users");
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
        const contest = await contestCollection
          .find(query)
          .skip(skip)
          .limit(parseInt(limit))
          .toArray();

        res.send({
          contest,
          total,
          page: parseInt(page),
          totalPages: Math.ceil(total / limit),
        });
      } catch (err) {
        res
          .status(500)
          .send({ message: "Failed to fetch contests", error: err.message });
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
    app.get("/contest/my/created", async (req, res) => {
      try {
        const contests = await contestCollection
          .find({ creatorEmail: req.user.email })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(contests);
      } catch (err) {
        res
          .status(500)
          .send({ message: "Failed to fetch contests", error: err.message });
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
        res
          .status(500)
          .send({ message: "Failed to create contest", error: err.message });
      }
    });

    app.delete("/contest/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await contestCollection.deleteOne(query);
      res.send(result);
    });

    //payment relative api

    app.post("/payment/create-indent", async (req, res) => {
      try {
        const { amount } = req.body;
        const paymentInfo = await stripe.paymentIntents.create({
          amount: amount * 100,
          currency: "usd",
          payment_method_types: ["card"],
        });
        res.send({
          clientSecret: paymentInfo.client_secret,
        });
      } catch (err) {
        res.status(500).send({
          message: "Payment intent failed",
          error: err.message,
        });
      }
    });

    // participant
    app.post("/participants", verifyToken, async (req, res) => {
      try {
        const { contestId, paymentId, amount } = req.body;
        const queryId = { _id: new ObjectId(contestId) };

        // Fixed: use queryId instead of undefined 'id'
        const contest = await contestCollection.findOne(queryId);

        if (!contest || contest.status !== "approved") {
          return res.status(400).send({
            message: "Contest not available",
          });
        }

        // Check if user already participated
        const existingParticipation = await participationCollection.findOne({
          userEmail: req.user.email,
          contestId: contestId,
        });

        if (existingParticipation) {
          return res.status(400).send({ message: "Already registered" });
        }

        const participation = {
          userEmail: req.user.email,
          contestId,
          paymentId,
          amount,
          paymentDate: new Date(),
        };

        await participationCollection.insertOne(participation);

        await contestCollection.updateOne(queryId, {
          $inc: { participantsCount: 1 },
        });

        await usersCollection.updateOne(
          { email: req.user.email },
          { $inc: { contestsParticipated: 1 } },
        );

        res.send({
          message: "Successfully Registered",
          participantsCount: (contest.participantsCount || 0) + 1,
        });
      } catch (err) {
        console.error("Participation error:", err);
        if (err.code === 11000) {
          return res.status(400).send({ message: "Already registered" });
        }
        res.status(500).send({
          message: "Registration failed",
          error: err.message,
        });
      }
    });

    app.get("/participants/check/:contestId", verifyToken, async (req, res) => {
      try {
        const { contestId } = req.params;
        const participation = await participationCollection.findOne({
          userEmail: req.user.email,
          contestId: contestId,
        });
        res.send({ participated: !!participation });
      } catch (err) {
        res.status(500).send({ message: "Check failed", error: err.message });
      }
    });
  } catch (err) {
    console.log(err);
  }
}

run();

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
});
