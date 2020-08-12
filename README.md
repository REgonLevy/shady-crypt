# SHADY-CRYPT.js

## About Shady Crypt:

Shady Crypt is a new password hashing and cryptographically secure pseudo-random number generator (CSPRNG) library, optimized from the ground up to run natively on Node.js / the Chrome V8 JavaScript engine.

### Hashing Algorithm

With the notable exceptions of MD5 and SHA-1 [1], most modern hash functions are not practically susceptible to collision/second pre-image attacks -- although the fixed 184 bit digest size of BCrypt does theoretically open the door in this regard [2]. Rather, the main line of attack has been brute-force password guessing, guided by dictionaries, pattern checking, word list substitution, etc. This makes it imperative that a chosen hashing algorithm does not allow an attacker to make too many guesses too quickly.

Unfortunately, many commonly used hashing algorithms are highly parallelizable, allowing password guessing to be accelerated tremendously on specialized hardware, including application-specific integrated circuits (ASICs), field-programmable gate arrays (FPGAs), and high-end graphical processing units (GPUs) [3]. Ntantogian, et al, were able to achieve a rate of over 21 billion hashes per second from the MD5 algorithm utilizing an NVIDIA GTX 1070 graphics card -- currently available refurbished for around $400. And even more powerful GPUs are easily rented on cloud platforms such as AWS, Google Cloud, Oracle, and Microsoft Azure [4].

BCrypt was introduced in 1999 in response to such parallel computing / hardware-accelerated password guessing concerns when the main threat were ASICs with low gate counts [5]. However, with recent advances in FPGA technology, there are now published BCRYPT implementations that achieve a high level of parallelization in embedded hardware devices [6] [7].

Later memory hard functions (MHFs) such as SCrypt and Argon2 took a different tactic, using the physical memory as much as possible to limit the level of parallelism that an attacker could achieve and thus significantly increasing the cost required to crack a password with specialized hardware. However, with the rise of high bandwidth memory (HBM) enhanced FPGAs [8], the long-term soundness of this approach is somewhat in doubt. Moreover, the amount of memory consumption needed to implement Argon2 effectively as an MHF can also open the door to denial of service (DoS) attacks due to the substantial physical memory requirements of responding to multiple concurrent login attempts.

Shady Crypt was designed with a different, somewhat simpler approach in mind: An adjustable-speed hashing algorithm that maximizes the critical path length in order to minimize the *theoretically possible* speedup from parallel computation (cf. Amdahl’s Law [9]). If an attacker has K times the *sequential processing power* (but not necessarily K times the memory), the attacker will be able to run the algorithm K times as quickly. But they will have to pay full price for that extra computing power, as opposed to obtaining the same speedup by buying FPGAs / renting GPUs and parallelizing the algorithm.

Like BCrypt, Shady Crypt makes frequent access to a table that is constantly altered throughout the algorithm execution. This sort of pseudorandom access to memory, while fast on a CPU, is much less so on a GPU, where memory is shared and all cores compete for control of the internal memory bus.

However, Shady Crypt also utilizes the ranged Asymmetric Numeral System (rANS) [10] and tabled Asymmetric Numeral System (tANS) [11] approaches of Jarek Duda [12] [13] [14] in combination with multiple different methods (most obvious, some perhaps not so much) in order to ensure that most of the algorithm's operations must be performed sequentially in order to arrive at the correct hashed output.

### Implementation
				
Shady Crypt is implemented in -- and intentionally designed to be optimized for -- WebAssembly. This choice was made both for smooth implementation in the Node.js environment as well as to facilitate future applications with the emerging “server relief” approaches [3] [5] that allow significant amounts of the computational load of hashing to be shifted to the client-side.

While the .WAT assembly file is the source code for the .wasm WebAssembly binary used in the npm package, we have also provided a fully-functional variant of the main hashing algorithm written in C, with annotations of the variables that should allow the reader to analyze/critique/attempt to parallelize the algorithm. 

However, the reader should be aware -- as per above -- that this C file was written to optimize initial compilation to .WAT assembly using LLVM and Binaryen. If you think it looks ugly (and it does), please feel empowered to offer improvements as pull requests.

### CSPRNG

The Shady Crypt library also includes a native JavaScript implementation of a cryptographically secure pseudo-random number generator (CSPRNG) based upon the above principles that passes the complete TestU01 [15] 160-statistic "Big Crush" testing battery (which the reader may confirm by installing TestU01 and then compiling and running the attached test programs -- see "testing," below). The Shady Crypt CSPRNG runs at about half the speed of the native (and highly insecure) Math.random() method, but significantly faster than any other CSPRNG for JavaScript/Node.js of which we are aware.

## Installation:

To install via NPM, run:
```
npm install shady-crypt
```

## Usage:

To use Shady Crypt, you must first require in the package:

```
const shady = require('shady-crypt');
```

In order to hash a password, simply provide the password and desired “work factor” between 1 and 262143 (the default value of 1 is sufficient, with a time cost of 100 to 110 ms on most servers -- each additional increment gives a c. 50 ms increase in time cost). Shady Crypt will automatically generate a unique salt each time you hash a password (in the example below, `password` is the plain-text password as a string and `hash` is the hashed output for that user, containing both salt and hash):

```
shady.hash(password, 1, hash => {

    // Do something with the hash / store it somewhere.

}, error => {

    // Handle error.

});
```

In order to check a password against a stored hash value, enter the password (`password`) and stored hash (`hash`):

```
shady.verify(password, hash, result => {

    // Do something with the true/false result of whether the password was verified against the stored hash.

}, error => {

    // Handle error.
    
})
```
To generate a secure random floating point number between 0 and 1 (the same format as Math.random() ), first create a new random number generator by invoking the Shady Crypt random method (you must invoke the method because each new generator stores its seed / state / table information as a closure):


```
const rand = shady.random();
```

Then use your new generator to generate random numbers the same as you would use Math.random():


```
let x = rand();		// x will be a value between 0 and 1;

let y = Math.floor(rand() * 20); 	// y will be an integer between 0 and 19
```


The shady.randomInt() method works the same way except the result is a random signed, 32 bit integer between -2147483648 and 2147483647:

```
const randInt = shady.randInt();

let x = randInt();		
// x will be an integer between -2147483648 and 2147483647.

let y = randInt() < 0; 	
// y will have a 50-50 chance of being either true (if the number is negative) or false.
```

## Testing: 

In order to test both the both the Shady Crypt hashing algorithm and CSPRNG, you will need to download and install the TestU01 suite [15] by running the following commands:
```
mkdir TestU01
cd TestU01
basedir=`pwd`
curl -OL http://simul.iro.umontreal.ca/testu01/TestU01.zip
unzip -q TestU01.zip
cd TestU01-1.2.3
./configure --prefix="$basedir"
make -j 6
make -j 6 install
cd ..
    mkdir lib-so
    mv lib/*.so lib-so/.
```
After the TestU01 suite is installed, compile the test programs as follows. To test the CSPRNG:
```
gcc -std=c99 -Wall -O3 -o crush_tests crush_tests.c -Iinclude -Llib -ltestu01 -lprobdist -lmylib -lm
```
To test the hash digests:
```
gcc -std=c99 -Wall -O3 -o rabbit_test_on_digests rabbit_test_on_digests.c -Iinclude -Llib -ltestu01 -lprobdist -lmylib -lm
```
To generate the hashes.bin output file for the digest test, simply run the generate_digest_binaries.js script in Node.js:
```
node generate_digest_binaries.js 
```

## References:
			
[1] Andreeva, E., Bouillaguet, C., Dunkelman, O. et al, “New Second-Preimage Attacks on Hash Functions.” J Cryptol 29, 657–696 (2016). 

[2] Dooley, J. F., History of Cryptography and Cryptanalysis: Codes, Ciphers, and Their Algorithms (Springer, 2018), pp. 181-183.

[3] Ntantogian C., Malliaros S. and Xenakis C., “Evaluation of password hashing schemes in open source web platforms,” Computers & Security, 84, (2019).

[4] “GPU Cloud Computing Solutions,” NVIDIA [Online]. Available: https://www.nvidia.com/en-us/data-center/gpu-cloud-computing/ [Accessed August 12, 2020].

[5] Contini, S., “Method to protect passwords in databases for web applications,” IACR Cryptology ePrint Archive, 387 (2015).

[6]  Wiemer, F. and Zimmermann, R.,  “High-speed implementation of bcrypt password search using special-purpose hardware,” in International Conference on ReConFigurable Computing and FPGAs (2014).	

[7]  Malvoni, K., Designer, S., and Knezovic, J., “Are Your Passwords Safe: Energy-Efficient Bcrypt Cracking with Low-Cost Parallel Hardware,” in 8th USENIX Workshop on Offensive Technologies (2014). 

[8] Wang, Z., Huang, H.,  Zhang, J. and Alonso, G., “Benchmarking High Bandwidth Memory on FPGAs,” (2020). Preprint. Available: https://arxiv.org/pdf/2005.04324.pdf [Accessed August 12, 2020].

[9] Hill, M. D., and Marty, M. R., “Amdahl's Law in the Multicore Era,” in Computer, 41 (2008), pp. 33-38.	

[10] Giesen, F., https://github.com/rygorous/ryg_rans. [Accessed: August 12, 2020]. 

[11] Duda, J. https://github.com/JarekDuda/AsymmetricNumeralSystemsToolkit [Accessed: August 12, 2020].	

[12]  Duda, J., “Asymmetric numeral systems”. In: ArXiv e-prints (2009). arXiv: 0902.0271 [cs.IT].	

[13]  Duda., J.,  “Asymmetric numeral systems: entropy coding combining speed of Huffman coding with compression rate of arithmetic coding”. In: ArXiv e-prints (2013). arXiv: 1311.2540 [cs.IT].

[14] Duda, J., and Niemiec, M., “Lightweight compression with encryption based on Asymmetric Numeral Systems”. In: ArXiv e-prints (2016). arXiv: 1612.04662 [cs.IT].

[15] L’Ecuyer, P. and Simard, R., TestU01: A software library in ANSI C for empirical testing of random number generators, User's Guide, DIRO, University of Montreal (2013), http://simul.iro.umontreal.ca/testu01/.	
