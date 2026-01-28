AMD USB4 NET
===================================
Version 1.0.0.6

Description
-----------
AMD USB4NET is a NDIS driver used by Interdomain tunnel to create network adapters to be used only with AMD USB4 CM driver
	
### Operating System Supported:

* Microsoft Windows® 10 (64 bit)

Installation Instructions
-------------------------

**NOTE**: Find a device with a name as "Universal Serial Bus Controller" with device ID's  "162E/162F" or "1668/1669 or 15C4/15C5" in device manager.
If found, this driver is applicable. We can install it by following below instructions.

1. Open command window with admin mode and browse to path of AMD USBNet driver
2. Install AMD USB4NET with following command
3. "pnputil /add-driver amdusb4net.inf /install"

Uninstall Instructions:
---------------------------

We can uninstall it by following below instructions.
		
How to find OEM"number".inf to uninstall:


1. Open command mode with admin mode
2. Run PNPutil /enum-drivers > c:\1.txt
3. Open 1.txt and locate OEM**.inf mapping to AMD USB4NET diver
4. uninstall with following command
5. "pnputil /delete-driver oem**.inf /uninstall"

For Example if the OEM file number is OEM32.inf

	"pnputil /delete-driver oem32.inf /uninstall"

Update Instructions:
---------------------------

**NOTE**: To Update AMD USB4NET We need to uninstall the existing version of the driver and then install the latest version of the driver.

Copyright:
----------
(c) Copyright 2023 Advanced Micro Devices, Inc.All rights reserved.

LIMITATION OF LIABILITY:THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, 
NONINFRINGEMENT OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY 
DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF 
OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION 
OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES, THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the Materials nor any responsibility to support or update the Materials.AMD 
retains the right to make changes to its test specifications at any time,without notice. NO SUPPORT OBLIGATION:AMD is not obligated to furnish, support, 
or make any further information, software, technical information, know-how, or show-how available to you.

U.S. GOVERNMENT RESTRICTED RIGHTS:The Materials and documentation are provided with RESTRICTED RIGHTS.Use, duplication or disclosure by the Government 
is subject to restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq, or its successor.Use of the Materials by the Government constitutes 
acknowledgment of AMD's proprietary rights in them.


