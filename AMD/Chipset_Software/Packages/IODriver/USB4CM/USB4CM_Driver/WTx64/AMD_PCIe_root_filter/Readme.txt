AMD USB4 PCIe Filter Driver
===================================
Version 1.0.0.10

Description
-----------
AMD USB4 PCIe Filter Driver monitors D0Entry and D0Exit (i.e.,Device Power States) of PCIe Express Root on which this driver is installed.
Based on the device power states this filter driver indicates its current power states to AMD USB4 CM Driver.
	
### Operating System Supported:

* Microsoft Windows® 10 (64 bit)

Pre-requisite
--------------
"AMD USB4 Host Router" driver must be installed before installing "AMD USB4 PCIe Filter Driver".

Installation Instructions
----------------------------------

**NOTE**: As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation 
as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. Find two devices with name as "PCI Express Root Port" with device ID's "PCI\VEN_1022&DEV_14CD" or "PCI\VEN_1022&DEV_14EF".
5. Click on Update the driver 
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software", click "Finish" to complete the installation.
9. Repeat step 4-8 for installing this PCIe Filter driver on another PCIe Express Root Port with the same device ID as mentioned in step 4.
 
Update Instructions:
------------------------------------

**NOTE**: As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation
as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager.
4. There should be a device section named "PCI Express Root Port" with device ID's "PCI\VEN_1022&DEV_14CD".
5. Check for amdusb
5. Right-click on "PCI USB Bus" and click on "Update Driver".
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software", click "Finish" to complete the installation.
9. Repeat step 4-8 for updating this PCIe Filter driver on another PCIe Express Root Port with the same device ID as mentioned in step 4.

Uninstall Instructions:
---------------------------------------

**NOTE**: As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device section named "PCI Express Root Port" with device ID's "PCI\VEN_1022&DEV_14CD".
5. Right-click on the "PCI USB Bus" and click on "Uninstall".
6. Select "Delete the driver software for this device".
7. Click "OK".

Copyright
---------------------------
(c) Copyright 2023 Advanced Micro Devices, Inc.All rights reserved.

LIMITATION OF LIABILITY:THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT
OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING,
WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD
HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the Materials nor any responsibility to support or update the Materials.AMD retains the right
to make changes to its test specifications at any time,without notice.NO SUPPORT OBLIGATION:AMD is not obligated to furnish, support, or make any further information,
software, technical information, know-how, or show-how available to you.

U.S. GOVERNMENT RESTRICTED RIGHTS:The Materials and documentation are provided with RESTRICTED RIGHTS.Use, duplication or disclosure by the Government is subject to
restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq, or its successor.Use of the Materials by the Government constitutes acknowledgment of AMD's
proprietary rights in them.




