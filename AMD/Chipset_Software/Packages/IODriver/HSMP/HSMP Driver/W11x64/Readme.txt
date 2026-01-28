AMD Host System Management Port
===================================
Version 1.0.0.5 Release Notes

(c) Copyright 2025 Advanced Micro Devices, Inc.  All rights reserved.

Contents

 1  Overview
 2  Required Files
 3  Installation/Update/Uninstallation
 4  Troubleshooting


1  Overview
------------
The Package provides .inf, .sys, .cat files for the Driver which will act as an interface to get/set Host System Management functionalities via SMN Mailbox
Registers and provides User level access.


2  Required Files
-----------------

To install the driver, the following files are required:

AmdHSMPDriver.inf         Installation Setup Script
AmdHSMPDriver.sys         System File
AmdHSMPDriver.cat         Digital Signature


3  Installation/Uninstallation

Installation Instructions
-------------------------

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device in the section named "Other Devices" with name "Unknown Device", with Hardware Id as *AMDI0097*.
5. Right-click on "Unknown Device” and click on "Update Driver".
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software”, click "Finish" to complete the installation.
9. Driver gets installed successfully with display name "AMD Host System Management Port".

Update Instructions
-------------------------

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device section named "AMD Host System Management Port".
5. Right-click on "AMD Host System Management Port", and click on "Update Driver".
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software", click "Finish" to complete the Update.

Uninstall Instructions:
-----------------------

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device with name "AMD Host System Management Port".
5. Right-click on the "AMD Host System Management Port", and click on "Uninstall".
6. Select "Delete the driver software for this device".
7. Click "OK".


4  Troubleshooting

If you should encounter any problems, uninstall the driver and reboot.


Copyright:
----------
(c) Copyright 2025 Advanced Micro Devices, Inc.All rights reserved.

LIMITATION OF LIABILITY:THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the Materials nor any responsibility to support or update the Materials.AMD retains the right to make changes to its test specifications at any time,without notice.NO SUPPORT OBLIGATION:AMD is not obligated to furnish, support, or make any further information, software, technical information, know-how, or show-how available to you. 

U.S. GOVERNMENT RESTRICTED RIGHTS:The Materials and documentation are provided with RESTRICTED RIGHTS.Use, duplication or disclosure by the Government is subject to restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq, or its successor.Use of the Materials by the Government constitutes acknowledgment of AMD's proprietary rights in them.

