"use strict";

const fs = require('fs');

function toUint8Array(buff){

  var u = new Uint8Array(buff.length);

  for (var i = 0; i < buff.length; ++i) {
    u[i] = buff[i];
  }

  return u;
}

function loadWebAssembly(filename, imports){

  const buffer = toUint8Array(fs.readFileSync(filename));

  return WebAssembly.compile(buffer).then(module => {

    imports = imports || {};
    imports.env = imports.env || {};
    imports.env.memoryBase = imports.env.memoryBase || 0;
    imports.env.tableBase = imports.env.tableBase || 0;

    if (!imports.env.memory) {
      imports.env.memory = new WebAssembly.Memory({ initial: 256 });
    }

    if (!imports.env.table) {
      imports.env.table = new WebAssembly.Table({ initial: 0, element: 'anyfunc' });
    }

    return new WebAssembly.Instance(module, imports);

  });
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const aTable = {"A": 0, "B": 1, "C": 2, "D": 3, "E": 4, "F": 5, "G": 6, "H": 7, "I": 8, "J": 9, "K": 10, "L": 11, "M": 12, "N": 13, "O": 14, "P": 15, "Q": 16, "R": 17, "S": 18, "T": 19, "U": 20, "V": 21, "W": 22, "X": 23, "Y": 24, "Z": 25, "a": 26, "b": 27, "c": 28, "d": 29, "e": 30, "f": 31, "g": 32, "h": 33, "i": 34, "j": 35, "k": 36, "l": 37, "m": 38, "n": 39, "o": 40, "p": 41, "q": 42, "r": 43, "s": 44, "t": 45, "u": 46, "v": 47, "w": 48, "x": 49, "y": 50, "z": 51, "0": 52, "1": 53, "2": 54, "3": 55, "4": 56, "5": 57, "6": 58, "7": 59, "8": 60, "9": 61, "+": 62, "/": 63};

const random = () => {
            
    var state = new Int32Array(4827);
    var c = Math.floor(Math.random() * 64) + (Math.floor(Math.random() * 64) << 6);
    var lcg = Math.floor(Math.floor(Math.random() * 256)) + (Math.floor(Math.random() * 256) << 8) + (Math.floor(Math.random() * 256) << 16) + (Math.floor(Math.random() * 256) << 24);
    var xors = Math.floor(Math.floor(Math.random() * 256)) + (Math.floor(Math.random() * 256) << 8) + (Math.floor(Math.random() * 256) << 16) + (Math.floor(Math.random() * 256) << 24);
    var s1, s2, ast, stream;
    var j = 4827 | 0;
    var k = 1023 | 0;
    var spread = new Int32Array(1024);
    var table = new Int32Array(1024);
    var sh = 13579|0;
    var mult = 69069|0;
    var flip = 1 << 31;
    var b = 2 ** 32;

    for(let i = 0; i < 4827; i++){
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        state[i] = lcg + xors;
    }

    let set = [...Array(1024).keys()];
    let t, x;

    for(let i = 1024; i > 0; i--){
        j = (j < 4826) ? j + 1 : 0;
        x = state[j];
        t = (x << 12) + c;
        c = (x >>> 20) - ((t ^ flip) < (x ^ flip));
        state[j] = ~(t - x);
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        x = Math.abs((state[j] + lcg + xors) % i);
        table[i - 1] = set[x];
        set.splice(x, 1);
    }

    for(let i = 0; i < 1024; i++){
        x = table[i];
        spread[x] = i;
    }

    ast = (lcg + xors) & 1023;

    return () => {
        let t, x, v, w, g;
        j = (j < 4826) ? j + 1 : 0;
        k = (k < 1023) ? k + 1 : 0;
        x = state[j];
        t = (x << 12) + c;
        c = (x >>> 20) - ((t ^ flip) < (x ^ flip));
        state[j] = ~(t - x);
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        x = (state[j] + lcg + xors) | 0;
        s1 = x & 31;
        s2 = x >>> 27;
        stream <<= 5;
        stream += ast & 31;
        ast = table[(s2 << 5) + (ast >> 5)];
        if((w = spread[k]) >> 5 !== s1){
            v = (state[j] & 31) + (s1 << 5);
            g = table[v];
            table[w] = g;
            table[v] = k;
            spread[k] = v;
            spread[g] = w;
        }
        return 0.5 + (x ^ stream) / b;
    };
};

const randomInt = () => {
             
    var state = new Int32Array(4827);
    var c = Math.floor(Math.random() * 64) + (Math.floor(Math.random() * 64) << 6);
    var lcg = Math.floor(Math.floor(Math.random() * 256)) + (Math.floor(Math.random() * 256) << 8) + (Math.floor(Math.random() * 256) << 16) + (Math.floor(Math.random() * 256) << 24);
    var xors = Math.floor(Math.floor(Math.random() * 256)) + (Math.floor(Math.random() * 256) << 8) + (Math.floor(Math.random() * 256) << 16) + (Math.floor(Math.random() * 256) << 24);
    var s1, s2, ast, stream;
    var j = 4827 | 0;
    var k = 1023 | 0;
    var spread = new Int32Array(1024);
    var table = new Int32Array(1024);
    var sh = 13579|0;
    var mult = 69069|0;
    var flip = 1 << 31;

    for(let i = 0; i < 4827; i++) {
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        state[i] = lcg + xors;
    }

    let set = [...Array(1024).keys()];
    let t, x;

    for(let i = 1024; i > 0; i--){
        j = (j < 4826) ? j + 1 : 0;
        x = state[j];
        t = (x << 12) + c;
        c = (x >>> 20) - ((t ^ flip) < (x ^ flip));
        state[j] = ~(t - x);
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        x = Math.abs((state[j] + lcg + xors) % i);
        table[i - 1] = set[x];
        set.splice(x, 1);
    }

    for(let i = 0; i < 1024; i++){
        x = table[i];
        spread[x] = i;
    }

    ast = (lcg + xors) & 1023;

    return () => {
        let t, x, v, w, g;
        j = (j < 4826) ? j + 1 : 0;
        k = (k < 1023) ? k + 1 : 0;
        x = state[j];
        t = (x << 12) + c;
        c = (x >>> 20) - ((t ^ flip) < (x ^ flip));
        state[j] = ~(t - x);
        lcg = (Math.imul(mult, lcg) + sh) | 0;
        xors ^= xors << 13;
        xors ^= xors >>> 17;
        xors ^= xors << 5;
        x = (state[j] + lcg + xors) | 0;
        s1 = x & 31;
        s2 = x >>> 27;
        stream <<= 5;
        stream += ast & 31;
        ast = table[(s2 << 5) + (ast >> 5)];
        if((w = spread[k]) >> 5 !== s1){
            v = (state[j] & 31) + (s1 << 5);
            g = table[v];
            table[w] = g;
            table[v] = k;
            spread[k] = v;
            spread[g] = w;
        }
        return x ^ stream;
    };
};

module.exports = {

    random: random,

    randomInt: randomInt,

    hash: (password, work, callback, error) => {

        const random = randomInt();
        
        return loadWebAssembly('hash.wasm').then(i => {

            const buff = new Uint8Array(i.exports.memory.buffer, 0, 100);

            let t;

            for(let i = 0; i < 3; i++){
                buff[i] = work & 63;
                work >>= 6;
            }

            for(let i = 3; i < 16; i++){
                let char = 0;
                for(let j = 0; j < 6; j++){
                    char += (random() & 1) << j;
                }
                buff[i] = char;
            }

            while(password.length < 72){
                password += password;
            }

            password = password.slice(0, 72);

            for(let i = 0; i < 72; i++){
                t = password.charCodeAt(i);
                if(t > 126) t = t % 95 + 32;
                buff[i + 16] = t;
            }

            i.exports.hash(buff.byteOffset);

            let hsh = '';

            for(let i = 0; i < 100; i++){
                hsh += alphabet[buff[i]];
            }

            return hsh;  

        }).then(x => callback(x)).catch(y => error(y));
    },

    verify: (password, hash, callback, error) => {

        return loadWebAssembly('hash.wasm').then(i => {

            const buff = new Uint8Array(i.exports.memory.buffer, 0, 100);

            let t;

            for(let i = 0; i < 16; i++){
                buff[i] = aTable[hash[i]];
            }

            while(password.length < 72){
                password += password;
            }

            password = password.slice(0, 72);

            for(let i = 0; i < 72; i++){
                t = password.charCodeAt(i);
                if(t > 126) t = t % 95 + 32;
                buff[i + 16] = t;
            }

            i.exports.hash(buff.byteOffset);

            let hsh = '';

            for(let i = 0; i < 100; i++){
                hsh += alphabet[buff[i]];
            }

            return hsh === hash;

        }).then(x => callback(x)).catch(y => error(y));
    }

}