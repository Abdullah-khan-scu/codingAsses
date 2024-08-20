This is a python script to parse flow log data and maps it to different tags. The example taken in the input.txt is the same from the email. The lookup table is also from the email.

Some Assumptions:
The length of the flow log taken is 14. In the example given in the email in one line there 14 fields thats why.
There are many protocols but I have taken 3 that is tcp,icmp and udp. In the future if need be they can be added in the "PROTOCOL_MAP"
LookUp table is usually in CSV format but due to the requirement stating that the input and the tag mapping both are plain ascii text file so here I have used .txt files only.

there are 2 files:
lookup_table.txt : Tag mapping
input.txt : Flow Logs

And the output of the program is stored in the output.txt

To Run this file run this command using the following format:

python script.py <lookup_table.txt> <input.txt> <output.txt>

Example:
```
python script.py lookup_table.txt input.txt output.txt
```
