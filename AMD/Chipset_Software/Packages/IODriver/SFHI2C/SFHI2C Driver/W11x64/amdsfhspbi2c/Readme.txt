AMD MP2 I2C Driver
Version 1.0.0.86 Readme Public

(c) Copyright 2017-24 Advanced Micro Devices, Inc.  All rights reserved.  

Contents

1. OS Support
2. Required Files
3. Installation/Uninstallation
4. Troubleshooting

OS supported 
* Microsoft Windows® 10 (64 bit)
* Microsoft Windows® 11 (64 bit)

2 Required Files

To install the driver, the following files are required:

amdsfhspbi2c.inf         installation setup script
amdsfhspbi2c.cat        digital signature
amdsfhspbi2c.sys        Binary File

3 Installation Instructions:

1) Right-click on "My Computer" and select "Properties".
2) Select the "Hardware Tab" and click on the "Device Manager" button.
3) Under "other devices", right-click on “device id AMDI0011/0 and AMDI0011/1”, select "Properties", and click on the “Details” tab to verify that the “Device Hardware Id” matches; if so, click on the “Driver” tab, and then click on “Update Driver…”
4) Follow the “Installation Wizard” prompts to install the amdsfhspbi2c.INF file.

4 Troubleshooting

If you should encounter any problems, uninstall the driver and reboot.












