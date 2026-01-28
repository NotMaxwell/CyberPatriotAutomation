=========================================================================
Copyright (c) 2025 ADVANCED MICRO DEVICES, INC. All Rights Reserved.
=========================================================================

AMD Sensor Fusion Hub
---------------------
AMD Sensor Fusion Hub (will be  referred as SFH device) is a  PCI Express Endpoint and Sensor UMDF driver.


Supported OS:
-------------
* Microsoft Windows® 11 (64 bit)

Supported chipsets:
-------------------

Ryzen

Supported Features:
------------------
The SFH Driver Support below list of features if supported by the firmware. SFH Driver discover features supported in the firmware and dynamically configure User Mode Driver according to the support provided by the firmware.

 * Primary Accelerometer and Screen Rotation Accelerometer (SRA)
 * Lid Angle Determination and Operating Mode
 * Gyroscope
 * Magnetometer
 * Compass
 * Ambient Light Sensor (ALS)
 * Proximity sensor

Installation Instructions:
--------------------------

Sequence of Driver Installation (Please follow order of installation):

Installation of KMDF Driver
  * Open device manager from the control panel and navigate to "Other Devices". Select the 'PCI' device with device id "PCI\VEN_1022&DEV_164A". Right click on the device and select "Update Driver".
  * On "How do you want to search for drivers?" window, click on "Browse my computer for driver software".
  * On the next window, click "Let me pick from a list of available drivers on my computer ".
  * Click Next and Select "Have Disk"... button, located on the bottom-right, under the text box.
  * Once the "Install from Disk" window appears, click on Browse...button on the bottom-right corner of the window.
  * Browse to the folder where the KMDF driver files are located
  * Select amdsfhkmdf.inf file in the file list and then touch or click the Open Button. Note: INF files are the only files that Device Manager accepts for driver setup.
  * Click OK on the Install from Disk window.
  * Choose the newly added hardware in the text box and then click Next
  * While on the Installing driver software... screen, which should only last for few to several seconds, Windows will use the instructions included in the INF file
  * Once the driver update process is complete, you should see a Windows has successfully updated your driver software window.

Installation of UMDF Driver
  * Open device manager from the control panel and navigate to "Other Devices". Select the 'unknown' device with device id "ACPI\AMDI0080". Right click on the device and select "Update Driver"
  * On "How do you want to search for drivers?" window, click on "Browse my computer for driver software".
  * On the next window, click "Let me pick from a list of available drivers on my computer ".
  * Click Next and Select "Have Disk"... button, located on the bottom-right, under the text box.
  * On the "Install from Disk" window that appears, click the Browse...button on the bottom-right corner of the window.
  * Browse to the folder where the UMDF driver files are located
  * Select amdsfhumdf.inf file in the file list and then touch or click the Open button. Note: INF files are the only files that Device Manager accepts for driver setup.
  * Click OK on the Install From Disk window.
  * Choose the newly added hardware in the text box and then click Next
  * While on the Installing driver software... screen, which should only last for few to several seconds, Windows will use the instructions included in the INF file
  * Once the driver update process is complete, you should see a Windows has successfully updated your driver software window.

Uninstallation Instructions:
----------------------------
1. Open Windows Device Manager
2. Find "Sensors" -> "AMD UMDF Sensor", right click and select Delete checkbox and "Uninstall"
3. Find "System devices" -> "AMD Sensor Fusion Hub", right click and select Delete checkbox and "Uninstall"


LIMITATION OF LIABILITY: THE MATERIALS ARE PROVIDED AS IS WITHOUT ANY EXPRESS OR IMPLIED WARRANTY OF ANY KIND INCLUDING WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT
OF THIRD-PARTY INTELLECTUAL PROPERTY, OR FITNESS FOR ANY PARTICULAR PURPOSE. IN NO EVENT SHALL AMD OR ITS SUPPLIERS BE LIABLE FOR ANY DAMAGES WHATSOEVER (INCLUDING,
WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION) ARISING OUT OF THE USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD 
HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES. BECAUSE SOME JURISDICTIONS PROHIBIT THE EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
THE ABOVE LIMITATION MAY NOT APPLY TO YOU.

AMD does not assume any responsibility for any errors which may appear in the Materials nor any responsibility to support or update the Materials.
AMD retains the right to make changes to its test specifications at any time, without notice.NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make 
any further information, software, technical information, know-how, or show-how available to you. 

U.S.GOVERNMENT RESTRICTED RIGHTS: The Materials and documentation are provided with RESTRICTED RIGHTS. Use, duplication or disclosure by the Government is subject to 
restrictions as set forth in FAR52.227014 and DFAR252.227-7013, et seq., or its successor. Use of the Materials by the Government constitutes acknowledgment of AMD's 
proprietary rights in them.

