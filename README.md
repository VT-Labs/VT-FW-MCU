# VT-FW-MCU
READ CAREFULLY! 
THE DATA IS PROVIDED “AS IS” AND “AS AVAILABLE”.  WE SHALL NOT BE LIABLE FOR DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING LOST PROFITS AND PROPERTY DAMAGE.  IN NO EVENT SHALL OUR TOTAL LIABILITY TO YOU FOR ALL DAMAGES, LOSSES AND CAUSES OF ACTION.

You may not decompile, reverse engineer or disassemble any data of this repository. The Data may be available only for limited periods of time and may be removed, replaced, changed or updated at any time at our sole discretion and with or without notice to you.

# VT-FW-agent APIs
The security agent will monitor the suspicious or malicious activities on CAN Bus. These APIs can be integrated into automotive ECUs to defend against abnormal activities.

# input traffic format
example:
{"timestamp":1500417011404,"seq":0,"id":0x78,"dlc":8,"data":[0x1,0x8,0x80,0x10,0x0,0x0,0x0,0x0]}

You have to convert your own CAN traffic files into this format before testing.

# testing dataset
The low false positive and high detection rate are two critical factors for FW. The traffic files from two folders, "normal" and "attack", are used to test the false positive and detection rate. Attack traffic include various attck/hack scenarios, such as fuzzying, DoS, spoof, scan, etc.,

Users can use their own tools to generate more attacking traffic datasets. For example, if you have CAN Bus penetration testing tool or device, you can use the output traffic from that as the input feeds of the FW. Don't forget to convert the above format.


