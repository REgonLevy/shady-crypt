const shady = require('./exports.js');
const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const terminal = rl.output;
const input = rl.input;

function toUint8Array(buff) {

    var u = new Uint8Array(buff.length);
  
    for (var i = 0; i < buff.length; ++i) {
      u[i] = buff[i];
    }
  
    return u;
  }
  
  function loadWebAssembly(filename, imports) {
  
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

  const random = shady.randomInt();

  let password = undefined;

  const make = (password = "p@ssw0rd", kb = 1000) => loadWebAssembly('compressOOG.wasm').then(i => {

    const bites = new Uint8Array(1008*kb);

    for(let k = 0; k < 16 * kb; k++) {

    let password = "p@ssw0rd";

    const buff = new Uint8Array(i.exports.memory.buffer, 0, 100);
    let t;

    buff[0] = 1;
    buff[1] = 0;
    buff[2] = 0;    

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

    for(j = 0; j < 21; j++) {
        bites[k * 63 + j * 3] = buff[j * 4 + 16] + (buff[j * 4 + 17] << 6);
        bites[k * 63 + j * 3 + 1] = (buff[j * 4 + 17] >> 2) + (buff[j * 4 + 18] << 4);
        bites[k * 63 + j * 3 + 2] = (buff[j * 4 + 18] >> 4) + (buff[j * 4 + 19] << 2);
    }

}
    return bites;

}).then(bytes => {

const fd = fs.openSync("./testing.bin", "w");

fs.writeSync(fd, bytes, 0, kb * 1008, 0);

fs.close(fd, (error) => { 
    if (error) {
      console.error("Error closing file: ", error); 
      process.exit(1);
    } else { 
      console.log("Successfully created file.");
      process.exit(0);
    } 
  }); 
}).catch(error =>{
    console.error("Error hashing: ", error);
    process.exit(1);
});

terminal.write('The default password is "p@ssw0rd." Would you like to change it (yes/no)? ');

rl.on('line', data => {

    let response = data.toString().trim();

    if (response === 'y' || response === "yes") {
      terminal.write('\n');
      rl.pause();
      rl.resume();
      terminal.write('Please enter a new password: ');
    } else if (response === 'no' && response === "n"){
        terminal.write('\nHow many kilobytes do you want output (minimum is 128, it will take around 2 seconds / KB): ');
    } else if (!isNaN(Number(response))) {
        make(password, Number(response) > 128 ? Math.floor(Number(response)) : undefined);
    } else {
        password = response;
        terminal.write('\n');
        rl.pause();
        rl.resume();
        terminal.write('\nHow many kilobytes do you want output (minimum is 128, time cost is 1 to 2 seconds / kilobyte): ');
    }
    
});