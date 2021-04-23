const fastify  = require('fastify')({
    logger:true
});
const routes   = require('./routes');
const path     = require('path');
const Database = require('./database');

const db = new Database('feedback.db');

fastify.register(require('fastify-helmet'), {
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-eval'", "https://cdnjs.cloudflare.com/"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com/nes.css/", "https://fonts.googleapis.com/"],
            fontSrc: ["'self'", "https://fonts.gstatic.com/"],
            imgSrc: ["'self'", "data:"],
            childSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    
});
fastify.register(require('point-of-view'), {
  engine: {
    pug: require('pug')
  }
});
fastify.register(require('fastify-formbody'));
fastify.register(routes(db));
fastify.register(require('fastify-static'), {
    root: path.join(__dirname, 'public'),
    prefix: '/'
});

(async () => {
    await db.connect();
    await db.migrate();
    fastify.listen(1337, '0.0.0.0', (err, address) => {
        if (err) {
            fastify.log.error(err);
            process.exit(1);
        }
        fastify.log.info(`Server listening on ${address}`);
    });
})();