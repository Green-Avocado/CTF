const puppeteer = require('puppeteer');

const browser_options = {
    headless: true,
    args: [
        '--no-sandbox',
        '--disable-background-networking',
        '--disable-default-apps',
        '--disable-extensions',
        '--disable-gpu',
        '--disable-sync',
        '--disable-translate',
        '--hide-scrollbars',
        '--metrics-recording-only',
        '--mute-audio',
        '--no-first-run',
        '--safebrowsing-disable-auto-update'
    ]
};

async function purgeData(db){
    const browser = await puppeteer.launch(browser_options);
    const page = await browser.newPage();

    page.on("pageerror", function(err) {  
		theTempValue = err.toString();
		console.log("Page error: " + theTempValue); 
	});

    page.on('error', err=> {
        console.log('error happen at the page: ', err);
    });

    page.on('console', consoleObj => console.log(consoleObj.text()));

    await page.goto('http://127.0.0.1:1337/list', {
        waitUntil: 'networkidle2'
    });

    await browser.close();
    await db.migrate();
};

module.exports = { purgeData };
