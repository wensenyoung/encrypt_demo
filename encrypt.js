const crypto = require('crypto');
const fs = require('fs');
const uuid = require('uuid');
const pwd = process.cwd();


function aesEncrypt(data, key, iv) {
    let inputEncoding = 'base64';
    let outputEncoding = 'base64';
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let crypted = cipher.update(data, inputEncoding, outputEncoding);
    crypted += cipher.final(outputEncoding);
    return {
        text: crypted, tag: cipher.getAuthTag().toString('base64')
    }
}

function getEncryptData(path, key, iv) {
    let data = fs.readFileSync(path, {encoding: 'base64'});
    return aesEncrypt(data, key, iv)
}

function encryptFile(path, key, iv, target) {
    let tmp = path.split('/');
    let filename = tmp[tmp.length - 1];
    let newname = target || filename.slice(0, filename.lastIndexOf('.') + 1) + ".txt";

    let temp = getEncryptData(path, key, iv);
    fs.writeFileSync(newname, JSON.stringify(temp))
}


function aesDecrypt(data, key, iv, authTag) {
    let inputEncoding = 'base64';
    let outputEncoding = 'base64';
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(data, inputEncoding, outputEncoding);
    decrypted += decipher.final(outputEncoding);
    return Buffer.from(decrypted, 'base64')
}

function getDecryptData(path, key, iv) {
    let data = fs.readFileSync(path, {encoding: 'utf8'});
    let temp = JSON.parse(data);
    let text = temp.text;
    let authTag = Buffer.from(temp.tag, 'base64');
    let content = aesDecrypt(text, key, iv, authTag);
    return content
}

function decryptFile(path, key, iv, target) {
    let tmp = path.split('/');
    let filename = tmp[tmp.length - 1];
    let newname = target || filename.slice(0, filename.indexOf('.'));

    let content = getDecryptData(path, key, iv);
    fs.writeFileSync(newname, content)
}


function encryptdir(dir, target, key, iv) {
    if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
        fs.mkdirSync(target)
    }

    dirname = dir.slice(dir.lastIndexOf('/') + 1);
    let origin = './' + dirname;
    target = target + '/' + getRandomKey();

    let manifest = {};
    manifest[target] = origin;
    encryptdir_exe(dir, target, key, iv);
    let manifest_text = Buffer.from(JSON.stringify(manifest), 'utf-8').toString('base64');
    let data = aesEncrypt(manifest_text, key, iv);
    fs.writeFileSync(target + '/../manifest', JSON.stringify(data));

    function encryptdir_exe(dir, target, key, iv) {
        let filelist = fs.readdirSync(dir);
        if (!fs.existsSync(target) || !fs.statSync(target).isDirectory()) {
            fs.mkdirSync(target)
        }

        for (let file of filelist) {
            let name = getRandomKey();
            let path = dir + '/' + file;
            let dest = target + '/' + name;
            manifest[dest] = path;
            if (fs.statSync(path).isFile()) {
                console.log(path, dest);
                encryptFile(path, key, iv, dest)
            } else {
                encryptdir_exe(path, dest, key, iv)
            }
        }
    }
}


function decryptdir(dir, key, iv, target) {
    if (!dir.startsWith('./')) dir = './' + dir;
    let prefixLen = dir.slice(0, dir.lastIndexOf('/')).length;

    target = target || './';
    ensure_dir(target);

    let manifest = getManifest(dir, key, iv);
    decryptDir_exec(dir, key, iv);

    function decryptDir_exec(dir, key, iv) {
        let filelist = fs.readdirSync(dir);
        for (let name of filelist) {
            if (name !== 'manifest') {
                let path = '.' + (dir + '/' + name).slice(prefixLen);
                let realName = target + '/' + manifest[path];
                if (fs.statSync(path).isDirectory()) {
                    ensure_dir(realName);
                    decryptDir_exec(path, key, iv)
                } else {
                    decryptFile(path, key, iv, realName)
                }
            }
        }
    }

}


function ensure_dir(dir) {
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
        fs.mkdirSync(dir)
    }
}

function getRandomKey() {
    let uid = uuid.v1();
    return uid.split('-').join('').toUpperCase()
}

function getManifest(dir, key, iv) {
    let mainfest_path = dir + "/manifest";
    let data = getDecryptData(mainfest_path, key, iv);
    console.log(typeof data, data.toString('utf-8'));
    let manifest = JSON.parse(data);
    return manifest
}


function genKeyIV() {
    let key = crypto.randomBytes(24).toString('base64');
    let IV = crypto.randomBytes(8).toString('base64');
    console.log(key.length, IV.length);
    return key + "-" + IV
}


module.exports = {
    encrypt: function (file, key, target) {
        key = key || genKeyIV();
        let k = key.slice(0, 32);
        let iv = key.slice(33);

        let filename = file.slice(file.lastIndexOf('/') + 1);
        target = target || "./" + filename + '.enc';

        if (fs.statSync(file).isDirectory()) {
            encryptdir(file, target, k, iv)
        } else {
            encryptFile(file, k, iv, target)
        }

        console.log('encrypt done, key: ', k + '-' + iv)
    },


    decrypt: function (file, key, target) {
        let k = key.slice(0, 32);
        let iv = key.slice(33);

        if (fs.statSync(file).isDirectory()) {
            decryptdir(file, k, iv, target)
        } else {
            decryptFile(file, k, iv, target)
        }

        console.log('decrypt done')
    }
};