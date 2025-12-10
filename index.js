import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import Stripe from "stripe";
import {MongoClient, ObjectId, ServerApiVersion} from "mongodb";
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const stripe = new Stripe(process.env.STRIPE_PUBLIC_KEY)
app.use(cors());
app.use(express.json());

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
        const contestCollection = db.collection("contexts");
        const usersCollection = db.collection('users');
        const participantsCollection = db.collection('participation');
        const submissionCollection = db.collection('submissions');
        const paymentCol = db.collection('payments');
        const winnerCol = db.collection('winners');

        app.get('/contest', async (req, res) => {
            try {
                const {type, search, page = 1, limit = 10, status} = req.query; // status optional
                const query = {};

                if (status) query.status = status;

                if (type && type !== 'all') query.contestType = type;

                if (search) {
                    query.$or = [
                        {name: {$regex: search, $options: 'i'}},
                        {description: {$regex: search, $options: 'i'}}
                    ];
                }

                const skip = (parseInt(page) - 1) * parseInt(limit);
                const total = await contestCollection.countDocuments(query);
                const contest = await contestCollection
                    .find(query)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .toArray();

                res.send({contest, total, page: parseInt(page), totalPages: Math.ceil(total / limit)});
            } catch (err) {
                res.status(500).send({message: 'Failed to fetch contests', error: err.message});
            }
        });


        app.get("/contest/:id", async (req, res) => {
            const id = req.params.id;
            const query = {_id: new ObjectId(id)};
            const result = await contestCollection.findOne(query);
            res.send(result);
        });

        app.post("/contest", async (req, res) => {
            const contest = req.body;
            contest.createdAt = new Date().toISOString();
            const result = await contestCollection.insertOne(contest);
            res.send(result);
        });

        app.delete("/contest/:id", async (req, res) => {
            const id = req.params.id;
            const query = {_id: new ObjectId(id)};
            const result = await contestCollection.deleteOne(query);
            res.send(result);
        });

        //payment relative api

        app.post('/payment', async (req,res)=>{

        })

    } catch (err) {
        console.log(err);
    }
}

run();

app.listen(port, () => {
    console.log(`server is running on port ${port}`);
});
