const sqlite = require('sqlite-async');

class Database {
    constructor(db_file) {
        this.db_file = db_file;
        this.db = undefined;
    }
    
    async connect() {
        this.db = await sqlite.open(this.db_file);
    }

    async migrate() {
        return this.db.exec(`
            DROP TABLE IF EXISTS feedback;

            CREATE TABLE IF NOT EXISTS feedback (
                id         INTEGER      NOT NULL PRIMARY KEY AUTOINCREMENT,
                comment  VARCHAR(255) NOT NULL,
                created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
            );

            INSERT INTO feedback (comment) VALUES ('Issue #256 is the best issue so far. Keep up the good work.');
            INSERT INTO feedback (comment) VALUES ('Articles could be better. The memes are not very realistic.');
            INSERT INTO feedback (comment) VALUES ('This article is very specist. Humans are better than that.');
        `);
    }

    async addFeedback(comment) {
        return new Promise(async (resolve, reject) => {
            try {
                let stmt = await this.db.prepare('INSERT INTO feedback (comment) VALUES (?)');
                resolve(await stmt.run(comment));
            } catch(e) {
                reject(e);
            }
        });
    }

    async getFeedback() {
        return new Promise(async (resolve, reject) => {
            try {
                let stmt = await this.db.prepare('SELECT * FROM feedback');
                resolve(await stmt.all());
            } catch(e) {
                reject(e);
            }
        });
    }
}

module.exports = Database;