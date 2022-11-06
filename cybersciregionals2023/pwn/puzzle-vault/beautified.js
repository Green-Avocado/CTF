#!/usr/bin/env node

var fs = require('fs');
const readline = require('readline'),
    rl = readline['createInterface']({
        'input': process['stdin'],
        'output': process['stdout']
    });

function bad_password() {
    console['log']('\x0aWrong\x20password,\x20bye...');
}
console['log']('You\x20are\x20accessing\x20the\x20Puzzle\x20Vault\x0a'), rl['question']('What\x20is\x20the\x20password?:\x20', function(_0x2fa26d) {
    try {
        if (_0x2fa26d['length'] != 0x19) {
            bad_password();
            return;
        }
        if (_0x2fa26d[0x0] != 'T') {
            bad_password();
            return;
        }
        if (_0x2fa26d[0x2] != _0x2fa26d[0x4] || _0x2fa26d[0xa] != _0x2fa26d[0x15] || _0x2fa26d[0xb] != _0x2fa26d[0x16] || _0x2fa26d[0xc] != _0x2fa26d[0x17] || _0x2fa26d[0xd] != _0x2fa26d[0x18] || _0x2fa26d[0x6] != _0x2fa26d[0x13]) {
            bad_password();
            return;
        }
        if (_0x2fa26d[0x2] != String['fromCharCode'](0x65) || _0x2fa26d['charCodeAt'](0x6) != 0x73) {
            bad_password();
            return;
        }
        if (_0x2fa26d['charCodeAt'](0x7) * 0x100 + _0x2fa26d['charCodeAt'](0x3) != 0x4e72) {
            bad_password();
            return;
        }
        if (_0x2fa26d['charCodeAt'](0x5) * 0x539 + 0x7a69 != 0x1f7aa) {
            bad_password();
            return;
        }
        val = _0x2fa26d['charCodeAt'](0x9);
        if (String['fromCharCode']((val << 0x3 | val >> 0x5) & 0xff) != '2') {
            bad_password();
            return;
        }
        if (_0x2fa26d['substring'](0x15, 0x19)['split']('')['reverse']()['join']('') !== 'tlua') {
            bad_password();
            return;
        }
        nopass = 'No,\x20this\x20is\x20not\x20the\x20password';
        if (nopass[nopass['length'] - 0x17] != _0x2fa26d[0x1] || nopass[0x19] != _0x2fa26d[0x8]) {
            bad_password();
            return;
        }
        const _0x1a21fd = [0x20, 0x1d, 0x74, 0x6, 0x6, 0x7, 0x76];
        for (i = 0x0; i < _0x1a21fd['length']; i++) {
            if (String['fromCharCode'](_0x1a21fd[i] ^ nopass['charCodeAt'](0x9 + i)) != _0x2fa26d[0xe + i]) {
                bad_password();
                return;
            }
        }
        console['log']('\x0aCorrect!\x20Here\x20are\x20the\x20vault\x20contents:\x0a'), fs['readFile']('./vault.dat', {
            'encoding': 'utf-8'
        }, function(_0x19e5c7, _0x1e0ff4) {
            !_0x19e5c7 ? console['log'](_0x1e0ff4) : console['log'](_0x19e5c7);
        });
    } finally {
        rl['close']();
    }
});
