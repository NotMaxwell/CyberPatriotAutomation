ZenProM S0i3 Network Filter
===================================
Version 1.1.0.7


Description
-------------------------
ZenProM S0i3 Network filter is responsible for waking up the system on 
from soi3 state, on receiving Manageability Request on specified 
TCP ports.

### Operating System Supported:

* Microsoft Windows® 10 (64 bit)
* Microsoft Windows® 11 (64 bit)

### Known Issues:

* N\A

Revision History
-----------------
* Please see Releasenotes.txt for details of revision history.

Installation Instructions
-------------------------

**NOTE**: As with all driver installations on Windows, you need to login as Administrator or have administrator rights for your domain login.

To install the driver, copy the installation files to a temporary directory,

1. Open Command Prompt as Administrator.

2. Redirect to the folder containg the installation files.

3. Run netcfg /v /c s /l driver-binary-folder-path\ZenProMnf.inf /i ZenProMnf.

	Eg. netcfg /v /c s /l C:\Users\AdminUser\Desktop\ZenProMnf\ZenProMnf.inf /i ZenProMnf.
	
To verify the installation

1. Open Command Prompt.

2. Run netcfg -q <service-name>

	Eg. netcfg -q ZenProMnf
	
To uninstall the driver

1. Open Command Prompt as Administrator.

2. netcfg /u <service-name>

   netcfg /u ZenProMnf
   
Copyright
---------------------------
Copyright (c)2020-2025 AMD Corporation.  All rights reserved.

LIMITATION OF LIABILITY: THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT
OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING,
WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD 
HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the Materials nor any responsibility to support or update the Materials.
AMD retains the right to make changes to its test specifications at any time, without notice.NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make 
any further information, software, technical information, know-how, or show-how available to you. 

U.S.GOVERNMENT RESTRICTED RIGHTS: The Materials and documentation are provided with RESTRICTED RIGHTS.Use, duplication or disclosure by the Government is subject to 
restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq., or its successor.Use of the Materials by the Government constitutes acknowledgment of AMD's 
proprietary rights in them.



