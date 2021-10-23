import { MongoClient, MongoServerError, ObjectId } from 'mongodb';

let clientMDB;
let MDBConnect = null;

async function connectMDB() {
	clientMDB = new MongoClient(
		'mongodb+srv://admin:admin@cluster0.nvnc3.mongodb.net/myFirstDatabase?retryWrites=true&w=majority',
		{useNewUrlParser: true, useUnifiedTopology: true }
	);
	await clientMDB.connect();
	MDBConnect = clientMDB.db('auth-test');
	//MDBConnect = db.collection('documents');
	
	// add indexs
	await MDBConnect.collection('users').createIndex({email: 1}, {unique: true});
	await MDBConnect.collection('r_tokens').createIndex({user: 1}, {unique: true});
}

function getConnectMDB() {
	return MDBConnect;
}

export {connectMDB, getConnectMDB, MongoServerError, ObjectId}
