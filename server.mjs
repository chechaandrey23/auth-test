import crypto from 'crypto';

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import {connectMDB} from './mdb.mjs';
import {routers} from './app.mjs';

const app = express();
const port = 3003;

await connectMDB();

app.use(express.json());

app.use(cookieParser());

app.use(cors({
	origin: '*'
}));

app.use('/auth', routers);

app.listen(port, () => {
	console.log(`Example app listening at http://localhost:${port}`)
});
