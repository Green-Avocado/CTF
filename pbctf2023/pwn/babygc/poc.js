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
