const path              = require('path');
const express           = require('express');
const nunjucks          = require('nunjucks');
const router            = express.Router();

const EmailHelper = require('../helpers/EmailHelper');

router.get('/', (req, res) => {
    return res.sendFile(path.resolve('views/index.html'));
});

router.post('/api/enroll', (req, res) => {
	const { email } = req.body;

	if (email) {
		return EmailHelper.sendEmail(email)
			.then(data => {
				return res.send(data);
			})
			.catch(err => {
				return res.send(err)
			});
	}

	return res.json({
		response: 'Missing parameters or invalid email address',
		error: 1
	});
});

module.exports = router;