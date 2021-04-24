const bot = require('../bot');
const fs = require('fs');

let db;

async function router (fastify, options) {
	fastify.get('/', async (request, reply) => {
		return reply.type('text/html').send(fs.readFileSync('views/index.html',{encoding:'utf8', flag:'r'}));
	});

	fastify.get('/alien', async (request, reply) => {
		if (request.ip != '127.0.0.1') {
			return reply.code(401).send({ message: 'Only localhost is allowed'});
		}
		return reply.type('text/html').send(fs.readFileSync('views/alien.html',{encoding:'utf8', flag:'r'}));
	});

	fastify.get('/feedback', async (request, reply) => {
		return reply.type('text/html').send(fs.readFileSync('views/feedback.html',{encoding:'utf8', flag:'r'}));
	});

	fastify.post('/api/submit', async (request, reply) => {
		let { feedback } = request.body;
		
		if (feedback) {
			return db.addFeedback(feedback)
				.then(() => {
					bot.purgeData(db);
					reply.send({ message: 'The Galactic Federation has processed your feedback.' });
				})
				.catch(() => reply.send({ message: 'The Galactic Federation spaceship controller has crashed.', error: 1}));
		}

		return reply.send({ message: 'Missing parameters.', error: 1 });
	});

	fastify.get('/list', async (request, reply) => {
		if (request.ip != '127.0.0.1') {
			return reply.code(401).send({ message: 'Only localhost is allowed'});
		}
		return await db.getFeedback()
			.then(feedback => {
				if (feedback) {
					return reply.view('views/list.pug', { feedback: feedback });
				}
				return reply.send({ message: 'The Galactic Federation archives appear to be empty.' });
			})
			.catch(() => {
				return reply.send({ message: 'The Galactic Federation spaceship controller has crashed.' });
			});
	});
}

module.exports = database => {
	db = database;
	return router;
};