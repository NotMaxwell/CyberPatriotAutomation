AMD UART Controller Driver
===================================
Version 1.2.0.119

Description
-------------------------
This driver supports the UART controller in AMD chipsets.

	
### Operating System Supported:

* Microsoft Windows® 10 (64 bit)
* Microsoft Windows® 11 (64 bit)

### Known Issues:

* N\A

Revision History
-----------------
1.2.0.119 08/20/2024
* Updated linker settings to include /CETCOMPAT.
* Updated build script.
* Updated Copyright Information.

1.2.0.118 12/11/2023
* Windows 2024 support

1.2.0.116 10/25/2023
* Update FIFO size based on CPU family ID.

1.2.0.114 02/11/2022
* Fixed MITT failure issue on UART1

1.2.0.113 12/16/2020
* Added support for 4M Baudrate.

1.2.0.112 08/03/2020
* Fixed the acquire/release of the lock.
  -  Updated the CustomDMA flag properly.
  -  DFx support is mandatory from 20H1 OS.
  -  INF only change

1.2.0.111 03/11/2020
* Added new Device AMDI0022 for Acton

1.2.0.110 03/06/2020
* Added registry flag 'CustomDMA' in INF, Updated copyright, version

1.1.0.0046 03/28/2016
* Add Zeppelin support

1.1.0.0041 03/30/2015
* Add 32-bit OS support

1.0.0.0021 05/07/2014
* Initial release


Installation Instructions
-------------------------

**NOTE**:  As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device in the section named "Other Devices" with name "Unknown Device", with Hardware Id as *AMDI0020/AMDI0020/AMDI0022*.
5. Right-click on "Unknown Device", and click on "Update Driver".
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software", click "Finish" to complete the installation.
 
Update Instructions:
---------------------------

**NOTE**:  As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

To install the driver, copy the installation files to a temporary directory, then use the "Device Manager" to perform an "Update Driver" operation as follows.  

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device section named "AMD UART Controller"
5. Right-click on AMD UART Controller, and click on "Update Driver".
6. Select "Browse my computer for driver software".
7. Click "Browse" to choose the installation files and click "OK".
8. A box will appear: "The wizard has finished installing the software", click "Finish" to complete the installation.


Uninstall Instructions:
---------------------------

**NOTE**:  As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

1. Select "Control Panel" from Start Menu.
2. Select "Classic View" from the left pane.
3. Invoke Device Manager. 
4. There should be a device section named "AMD UART Controller" 
5. Right-click on the “AMD UART Controller”, and click on "Uninstall".
6. Select "Delete the driver software for this device".
7. Click "OK".

Copyright
---------------------------
(c) Copyright 2012~2024 Advanced Micro Devices, Inc.  All rights reserved.

LIMITATION OF LIABILITY:  THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION OR LIMITATION OF LIABILITY FOR
CONSEQUENTIAL OR INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the 
Materials nor any responsibility to support or update the Materials.  AMD
retains the right to make changes to its test specifications at any time, 
without notice.  NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make any further information, software, technical information, know-how, or 
show-how available to you. 

U.S. GOVERNMENT RESTRICTED RIGHTS: The Materials and documentation are provided with RESTRICTED RIGHTS.  Use, duplication or disclosure by the Government is subject to restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq., or its successor.  Use of the Materials by the Government constitutes acknowledgment of AMD's proprietary rights in them.

