const nodemailer = require('nodemailer');
const nunjucks   = require('nunjucks');

module.exports = {

    async sendEmail(emailAddress) {
        return new Promise(async (resolve, reject) => {
            try {
                let message = {
                    to: emailAddress,
                    subject: 'Enrollment is now under review ✅',
                };

                if (process.env.NODE_ENV === 'production' ) {

                    let gifSrc = 'minimakelaris@hackthebox.eu';
                    
                    message.html = nunjucks.renderString(`
                        <p><b>Hello</b> <i>${ emailAddress }</i></p>
                        <p>A cat has been deployed to process your submission 🐈</p><br/>
                        <img width="500" height="350" src="cid:{{ gifSrc }}"/></p>
                        `, { gifSrc }
                    );

                    message.attachments = [
                        {
                            filename: 'minimakelaris.gif',
                            path: __dirname + '/../assets/minimakelaris.gif',
                            cid: gifSrc
                        }
                    ];

                    let transporter = nodemailer.createTransport({
                        host: 'smtp.gmail.com',
                        port: 465,
                        secure: true,
                        auth: {
                            user: 'cbctf.2021.web.newjucks@gmail.com',
                            pass: '[REDACTED]',
                        },
                        logger: true
                    });

                    transporter.sendMail(message);

                    transporter.close();

                    resolve({ response: 'The email has been sent' });
                } else {
                    let gifSrc = '//i.pinimg.com/originals/bf/17/70/bf1770f704af814c3da78b0866b286c2.gif';

                    message.html = nunjucks.renderString(`
                        <p><b>Hello</b> <i>${ emailAddress }</i></p>
                        <p>A cat has been deployed to process your submission 🐈</p><br/>
                        <img width="540" height="304" src="{{ gifSrc }}"/></p>
                        `, { gifSrc }
                    );

                    let testAccount = await nodemailer.createTestAccount();

                    let transporter = nodemailer.createTransport({
                        host: 'smtp.ethereal.email',
                        port: 587,
                        auth: {
                            user: testAccount.user,
                            pass: testAccount.pass,
                        },
                        logger: true
                    });

                    let info = await transporter.sendMail(message);

                    transporter.close();
                  
                    resolve({ response: `<iframe 
                        style='height:calc(100vh - 4px); width:100%; box-sizing: border-box;' scrolling='no' frameborder=0 
                        src='${nodemailer.getTestMessageUrl(info)}'
                    >`});
                }
            } catch(e) {
                reject({ response: 'Something went wrong' });
            }
        })
    }
};