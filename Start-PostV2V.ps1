<#
.FUNCTIONALITY

-Created to cover to post Hyper-V to VMware migration activities

.SYNOPSIS

.NOTES
Change log

July 4, 2022: Initial version

July 7, 2022
-Logging to CSV added
-Install code for VMware tools

July 8, 2022
-Fix for password reg inject as per https://stackoverflow.com/questions/28352141/convert-a-secure-string-to-plain-text#comment104212383_40166959
-new script converted into function to remove ghost hyper-v nic at end
-Changed detection method for VM type to use another reg key
-Amended description on detection of VMXNET3

Oct 24, 2022
-Added wildcard for HV nics
-IF statement on V2V user account creation added
-Code added to remove prompt on VMT install noted on Win 2016

Oct 25, 2022
-Updated logic for creation of user V2V 

Oct 26, 2022
-Added back reboot @ end
-Added 'AutoLogonCount' Value "2"
-Windows update disabled at source , / enabled at destination

Oct 27, 2022
-V2V auto-logon removed
-Extra lines logged

.EXAMPLE
./Start-PostV2V.ps1

.NOTES

.Link

#>

##Variables and initial actions

IF (-not(test-path c:\admin\Build)) {

    New-Item -Path c:\Admin\Build -ItemType Directory

}

$OS = (Get-WMIobject -class win32_operatingsystem).Caption
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')
$ScriptLog = "c:\Admin\Build\HyperVisorDriverInstall-$LogTimeStamp.txt"
$VMType = (Get-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\SystemInformation -Name SystemManufacturer).SystemManufacturer
$Env:SEE_MASK_NOZONECHECKS = 1

Function Get-VMToolsInstalled {
    
    IF (((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {
        
        [int]$Version = "32"
    }

    IF (((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {

       [int]$Version = "64"
    }    

    return $Version
}

Function Write-CustomLog {
    Param(
    [String]$ScriptLog,    
    [String]$Message,
    [String]$Level
    
    )

    switch ($Level) { 
        'Error' 
            {
            $LevelText = 'ERROR:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor RED            
            } 
        
        'Warn'
            { 
            $LevelText = 'WARNING:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor YELLOW            
            } 

        'Info'
            { 
            $LevelText = 'INFO:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor GREEN            
            } 

        }
        
        Add-content -value "$Message" -Path $ScriptLog
}

### Remove-GhostNIC function

<#
.SYNOPSIS
   Removes ghost devices from your system

   https://raw.githubusercontent.com/istvans/scripts/master/removeGhosts.ps1

.DESCRIPTION
    This script will remove ghost devices from your system. These are devices that are present but have an "InstallState" as false. These devices are typically shown as 'faded'
    in Device Manager, when you select "Show hidden and devices" from the view menu. This script has been tested on Windows 2008 R2 SP2 with PowerShell 3.0, 5.1, Server 2012R2
    with Powershell 4.0 and Windows 10 Pro with Powershell 5.1. There is no warranty with this script. Please use cautiously as removing devices is a destructive process without
    an undo.

.PARAMETER filterByFriendlyName
This parameter will exclude devices that match the partial name provided. This paramater needs to be specified in an array format for all the friendly names you want to be excluded.
"Intel" will match "Intel(R) Xeon(R) CPU E5-2680 0 @ 2.70GHz". "Loop" will match "Microsoft Loopback Adapter".

.PARAMETER narrowByFriendlyName
This parameter will include devices that match the partial name provided. This paramater needs to be specified in an array format for all the friendly names you want to be included.
"Intel" will match "Intel(R) Xeon(R) CPU E5-2680 0 @ 2.70GHz". "Loop" will match "Microsoft Loopback Adapter".

.PARAMETER filterByClass
This parameter will exclude devices that match the class name provided. This paramater needs to be specified in an array format for all the class names you want to be excluded.
This is an exact string match so "Disk" will not match "DiskDrive".

.PARAMETER narrowByClass
This parameter will include devices that match the class name provided. This paramater needs to be specified in an array format for all the class names you want to be included.
This is an exact string match so "Disk" will not match "DiskDrive".

.PARAMETER listDevicesOnly
listDevicesOnly will output a table of all devices found in this system.

.PARAMETER listGhostDevicesOnly
listGhostDevicesOnly will output a table of all 'ghost' devices found in this system.

.PARAMETER force
If specified, each matching device will be removed WITHOUT any confirmation!

.EXAMPLE
Lists all devices
. "removeGhosts.ps1" -listDevicesOnly

.EXAMPLE
Save the list of devices as an object
$Devices = . "removeGhosts.ps1" -listDevicesOnly

.EXAMPLE
Lists all 'ghost' devices
. "removeGhosts.ps1" -listGhostDevicesOnly

.EXAMPLE
Lists all 'ghost' devices with a class of "Net"
. "removeGhosts.ps1" -listGhostDevicesOnly -narrowByClass Net

.EXAMPLE
Lists all 'ghost' devices with a class of "Net" AND a friendly name matching "Realtek"
. "removeGhosts.ps1" -listGhostDevicesOnly -narrowbyfriendlyname Realtek -narrowbyclass Net

.EXAMPLE
Save the list of 'ghost' devices as an object
$ghostDevices = . "removeGhosts.ps1" -listGhostDevicesOnly

.EXAMPLE
Remove all ghost devices EXCEPT any devices that have "Intel" or "Citrix" in their friendly name
. "removeGhosts.ps1" -filterByFriendlyName @("Intel","Citrix")

.EXAMPLE
Remove all ghost devices that have "Intel" in their friendly name
. "removeGhosts.ps1" -narrowByFriendlyName Intel

.EXAMPLE
Remove all ghost devices EXCEPT any devices that are apart of the classes "LegacyDriver" or "Processor"
. "removeGhosts.ps1" -filterByClass @("LegacyDriver","Processor")

.EXAMPLE
Remove all ghost devices EXCEPT for devices with a friendly name of "Intel" or "Citrix" or with a class of "LegacyDriver" or "Processor"
. "removeGhosts.ps1" -filterByClass @("LegacyDriver","Processor") -filterByFriendlyName @("Intel","Citrix")

.EXAMPLE
Remove all ghost network devices i.e. the ones with a class of "Net"
. "removeGhosts.ps1" -narrowByClass Net

.EXAMPLE
Remove all ghost devices without confirmation
. "removeGhosts.ps1" -Force

.NOTES
Permission level has not been tested.  It is assumed you will need to have sufficient rights to uninstall devices from device manager for this script to run properly.
#>

Function Remove-GhostNICs {
Param(
  [array]$FilterByClass,
  [array]$NarrowByClass,
  [array]$FilterByFriendlyName,
  [array]$NarrowByFriendlyName,
  [switch]$listDevicesOnly,
  [switch]$listGhostDevicesOnly,
  [switch]$Force
)

#parameter futzing
$removeDevices = $true
if ($FilterByClass -ne $null) {
    write-host "FilterByClass: $FilterByClass"
}

if ($NarrowByClass -ne $null) {
    write-host "NarrowByClass: $NarrowByClass"
}

if ($FilterByFriendlyName -ne $null) {
    write-host "FilterByFriendlyName: $FilterByFriendlyName"
}

if ($NarrowByFriendlyName -ne $null) {
    write-host "NarrowByFriendlyName: $NarrowByFriendlyName"
}

if ($listDevicesOnly -eq $true) {
    write-host "List devices without removal: $listDevicesOnly"
    $removeDevices = $false
}

if ($listGhostDevicesOnly -eq $true) {
    write-host "List ghost devices without removal: $listGhostDevicesOnly"
    $removeDevices = $false
}

if ($Force -eq $true) {
    write-host "Each removal will happen without any confirmation: $Force"
}

function Filter-Device {
    Param (
        [System.Object]$dev
    )
    $Class = $dev.Class
    $FriendlyName = $dev.FriendlyName
    $matchFilter = $false

    if (($matchFilter -eq $false) -and ($FilterByClass -ne $null)) {
        foreach ($ClassFilter in $FilterByClass) {
            if ($ClassFilter -eq $Class) {
                Write-verbose "Class filter match $ClassFilter, skipping"
                $matchFilter = $true
                break
            }
        }
    }
    if (($matchFilter -eq $false) -and ($NarrowByClass -ne $null)) {
        $shouldInclude = $false
        foreach ($ClassFilter in $NarrowByClass) {
            if ($ClassFilter -eq $Class) {
                $shouldInclude = $true
                break
            }
        }
        $matchFilter = !$shouldInclude
    }
    if (($matchFilter -eq $false) -and ($FilterByFriendlyName -ne $null)) {
        foreach ($FriendlyNameFilter in $FilterByFriendlyName) {
            if ($FriendlyName -like '*'+$FriendlyNameFilter+'*') {
                Write-verbose "FriendlyName filter match $FriendlyName, skipping"
                $matchFilter = $true
                break
            }
        }
    }
    if (($matchFilter -eq $false) -and ($NarrowByFriendlyName -ne $null)) {
        $shouldInclude = $false
        foreach ($FriendlyNameFilter in $NarrowByFriendlyName) {
            if ($FriendlyName -like '*'+$FriendlyNameFilter+'*') {
                $shouldInclude = $true
                break
            }
        }
        $matchFilter = !$shouldInclude
    }
    return $matchFilter
}

function Filter-Devices {
    Param (
        [array]$devices
    )
    $filteredDevices = @()
    foreach ($dev in $devices) {
        $matchFilter = Filter-Device -Dev $dev
        if ($matchFilter -eq $false) {
            $filteredDevices += @($dev)
        }
    }
    return $filteredDevices
}
function Get-Ghost-Devices {
    Param (
        [array]$devices
    )
    return ($devices | where {$_.InstallState -eq $false} | sort -Property FriendlyName)
}

# NOTE: White spaces are important in $setupapi for some reason!
$setupapi = @"
using System;
using System.Diagnostics;
using System.Text;
using System.Runtime.InteropServices;
namespace Win32
{
    public static class SetupApi
    {
         // 1st form using a ClassGUID only, with Enumerator = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           ref Guid ClassGuid,
           IntPtr Enumerator,
           IntPtr hwndParent,
           int Flags
        );
    
        // 2nd form uses an Enumerator only, with ClassGUID = IntPtr.Zero
        [DllImport("setupapi.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr SetupDiGetClassDevs(
           IntPtr ClassGuid,
           string Enumerator,
           IntPtr hwndParent,
           int Flags
        );
        
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiEnumDeviceInfo(
            IntPtr DeviceInfoSet,
            uint MemberIndex,
            ref SP_DEVINFO_DATA DeviceInfoData
        );
    
        [DllImport("setupapi.dll", SetLastError = true)]
        public static extern bool SetupDiDestroyDeviceInfoList(
            IntPtr DeviceInfoSet
        );
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiGetDeviceRegistryProperty(
            IntPtr deviceInfoSet,
            ref SP_DEVINFO_DATA deviceInfoData,
            uint property,
            out UInt32 propertyRegDataType,
            byte[] propertyBuffer,
            uint propertyBufferSize,
            out UInt32 requiredSize
        );
        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool SetupDiGetDeviceInstanceId(
            IntPtr DeviceInfoSet,
            ref SP_DEVINFO_DATA DeviceInfoData,
            StringBuilder DeviceInstanceId,
            int DeviceInstanceIdSize,
            out int RequiredSize
        );

    
        [DllImport("setupapi.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetupDiRemoveDevice(IntPtr DeviceInfoSet,ref SP_DEVINFO_DATA DeviceInfoData);
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct SP_DEVINFO_DATA
    {
       public uint cbSize;
       public Guid classGuid;
       public uint devInst;
       public IntPtr reserved;
    }
    [Flags]
    public enum DiGetClassFlags : uint
    {
        DIGCF_DEFAULT       = 0x00000001,  // only valid with DIGCF_DEVICEINTERFACE
        DIGCF_PRESENT       = 0x00000002,
        DIGCF_ALLCLASSES    = 0x00000004,
        DIGCF_PROFILE       = 0x00000008,
        DIGCF_DEVICEINTERFACE   = 0x00000010,
    }
    public enum SetupDiGetDeviceRegistryPropertyEnum : uint
    {
         SPDRP_DEVICEDESC          = 0x00000000, // DeviceDesc (R/W)
         SPDRP_HARDWAREID          = 0x00000001, // HardwareID (R/W)
         SPDRP_COMPATIBLEIDS           = 0x00000002, // CompatibleIDs (R/W)
         SPDRP_UNUSED0             = 0x00000003, // unused
         SPDRP_SERVICE             = 0x00000004, // Service (R/W)
         SPDRP_UNUSED1             = 0x00000005, // unused
         SPDRP_UNUSED2             = 0x00000006, // unused
         SPDRP_CLASS               = 0x00000007, // Class (R--tied to ClassGUID)
         SPDRP_CLASSGUID           = 0x00000008, // ClassGUID (R/W)
         SPDRP_DRIVER              = 0x00000009, // Driver (R/W)
         SPDRP_CONFIGFLAGS         = 0x0000000A, // ConfigFlags (R/W)
         SPDRP_MFG             = 0x0000000B, // Mfg (R/W)
         SPDRP_FRIENDLYNAME        = 0x0000000C, // FriendlyName (R/W)
         SPDRP_LOCATION_INFORMATION    = 0x0000000D, // LocationInformation (R/W)
         SPDRP_PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E, // PhysicalDeviceObjectName (R)
         SPDRP_CAPABILITIES        = 0x0000000F, // Capabilities (R)
         SPDRP_UI_NUMBER           = 0x00000010, // UiNumber (R)
         SPDRP_UPPERFILTERS        = 0x00000011, // UpperFilters (R/W)
         SPDRP_LOWERFILTERS        = 0x00000012, // LowerFilters (R/W)
         SPDRP_BUSTYPEGUID         = 0x00000013, // BusTypeGUID (R)
         SPDRP_LEGACYBUSTYPE           = 0x00000014, // LegacyBusType (R)
         SPDRP_BUSNUMBER           = 0x00000015, // BusNumber (R)
         SPDRP_ENUMERATOR_NAME         = 0x00000016, // Enumerator Name (R)
         SPDRP_SECURITY            = 0x00000017, // Security (R/W, binary form)
         SPDRP_SECURITY_SDS        = 0x00000018, // Security (W, SDS form)
         SPDRP_DEVTYPE             = 0x00000019, // Device Type (R/W)
         SPDRP_EXCLUSIVE           = 0x0000001A, // Device is exclusive-access (R/W)
         SPDRP_CHARACTERISTICS         = 0x0000001B, // Device Characteristics (R/W)
         SPDRP_ADDRESS             = 0x0000001C, // Device Address (R)
         SPDRP_UI_NUMBER_DESC_FORMAT       = 0X0000001D, // UiNumberDescFormat (R/W)
         SPDRP_DEVICE_POWER_DATA       = 0x0000001E, // Device Power Data (R)
         SPDRP_REMOVAL_POLICY          = 0x0000001F, // Removal Policy (R)
         SPDRP_REMOVAL_POLICY_HW_DEFAULT   = 0x00000020, // Hardware Removal Policy (R)
         SPDRP_REMOVAL_POLICY_OVERRIDE     = 0x00000021, // Removal Policy Override (RW)
         SPDRP_INSTALL_STATE           = 0x00000022, // Device Install State (R)
         SPDRP_LOCATION_PATHS          = 0x00000023, // Device Location Paths (R)
         SPDRP_BASE_CONTAINERID        = 0x00000024  // Base ContainerID (R)
    }
}
"@
Add-Type -TypeDefinition $setupapi

    #Array for all removed devices report
    $removeArray = @()
    #Array for all devices report
    $array = @()

    $setupClass = [Guid]::Empty
    #Get all devices
    $devs = [Win32.SetupApi]::SetupDiGetClassDevs([ref]$setupClass, [IntPtr]::Zero, [IntPtr]::Zero, [Win32.DiGetClassFlags]::DIGCF_ALLCLASSES)

    #Initialise Struct to hold device info Data
    $devInfo = new-object Win32.SP_DEVINFO_DATA
    $devInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($devInfo)

    #Device Counter
    $devCount = 0
    #Enumerate Devices
    while([Win32.SetupApi]::SetupDiEnumDeviceInfo($devs, $devCount, [ref]$devInfo)) {

        #Will contain an enum depending on the type of the registry Property, not used but required for call
        $propType = 0
        #Buffer is initially null and buffer size 0 so that we can get the required Buffer size first
        [byte[]]$propBuffer = $null
        $propBufferSize = 0
        #Get Buffer size
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, 0, [ref]$propBufferSize) | Out-null
        #Initialize Buffer with right size
        [byte[]]$propBuffer = New-Object byte[] $propBufferSize

        #Get HardwareID
        $propTypeHWID = 0
        [byte[]]$propBufferHWID = $null
        $propBufferSizeHWID = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, 0, [ref]$propBufferSizeHWID) | Out-null
        [byte[]]$propBufferHWID = New-Object byte[] $propBufferSizeHWID

        #Get DeviceDesc (this name will be used if no friendly name is found)
        $propTypeDD = 0
        [byte[]]$propBufferDD = $null
        $propBufferSizeDD = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, 0, [ref]$propBufferSizeDD) | Out-null
        [byte[]]$propBufferDD = New-Object byte[] $propBufferSizeDD

        #Get Install State
        $propTypeIS = 0
        [byte[]]$propBufferIS = $null
        $propBufferSizeIS = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, 0, [ref]$propBufferSizeIS) | Out-null
        [byte[]]$propBufferIS = New-Object byte[] $propBufferSizeIS

        #Get Class
        $propTypeCLSS = 0
        [byte[]]$propBufferCLSS = $null
        $propBufferSizeCLSS = 0
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo, [Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, 0, [ref]$propBufferSizeCLSS) | Out-null
        [byte[]]$propBufferCLSS = New-Object byte[] $propBufferSizeCLSS
        [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_CLASS, [ref]$propTypeCLSS, $propBufferCLSS, $propBufferSizeCLSS, [ref]$propBufferSizeCLSS)  | out-null
        $Class = [System.Text.Encoding]::Unicode.GetString($propBufferCLSS)

        #Read FriendlyName property into Buffer
        if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_FRIENDLYNAME, [ref]$propType, $propBuffer, $propBufferSize, [ref]$propBufferSize)){
            [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_DEVICEDESC, [ref]$propTypeDD, $propBufferDD, $propBufferSizeDD, [ref]$propBufferSizeDD)  | out-null
            $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBufferDD)
            #The friendly Name ends with a weird character
            if ($FriendlyName.Length -ge 1) {
                $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
            }
        } else {
            #Get Unicode String from Buffer
            $FriendlyName = [System.Text.Encoding]::Unicode.GetString($propBuffer)
            #The friendly Name ends with a weird character
            if ($FriendlyName.Length -ge 1) {
                $FriendlyName = $FriendlyName.Substring(0,$FriendlyName.Length-1)
            }
        }

        #InstallState returns true or false as an output, not text
        $InstallState = [Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_INSTALL_STATE, [ref]$propTypeIS, $propBufferIS, $propBufferSizeIS, [ref]$propBufferSizeIS)

        # Read HWID property into Buffer
        if(![Win32.SetupApi]::SetupDiGetDeviceRegistryProperty($devs, [ref]$devInfo,[Win32.SetupDiGetDeviceRegistryPropertyEnum]::SPDRP_HARDWAREID, [ref]$propTypeHWID, $propBufferHWID, $propBufferSizeHWID, [ref]$propBufferSizeHWID)){
            #Ignore if Error
            $HWID = ""
        } else {
            #Get Unicode String from Buffer
            $HWID = [System.Text.Encoding]::Unicode.GetString($propBufferHWID)
            #trim out excess names and take first object
            $HWID = $HWID.split([char]0x0000)[0].ToUpper()
        }

        #all detected devices list
        $device = New-Object System.Object
        $device | Add-Member -type NoteProperty -name FriendlyName -value $FriendlyName
        $device | Add-Member -type NoteProperty -name HWID -value $HWID
        $device | Add-Member -type NoteProperty -name InstallState -value $InstallState
        $device | Add-Member -type NoteProperty -name Class -value $Class
        if ($array.count -le 0) {
            #for some reason the script will blow by the first few entries without displaying the output
            #this brief pause seems to let the objects get created/displayed so that they are in order.
            sleep 1
        }
        $array += @($device)

        <#
        We need to execute the filtering at this point because we are in the current device context
        where we can execute an action (eg, removal).
        InstallState : False == ghosted device
        #>
        if ($removeDevices -eq $true) {
            #we want to remove devices so let's check the filters...
            $matchFilter = Filter-Device -Dev $device

            if ($InstallState -eq $False) {
                if ($matchFilter -eq $false) {
                    $message  = "Attempting to remove device $FriendlyName"
                    $confirmed = $false
                    if (!$Force -eq $true) {
                        $question = 'Are you sure you want to proceed?'
                        $choices  = '&Yes', '&No'
                        $decision = $Host.UI.PromptForChoice($message, $question, $choices, 1)
                        if ($decision -eq 0) {
                            $confirmed = $true
                        }
                    } else {
                        $confirmed = $true
                    }
                    if ($confirmed -eq $true) {
                        Write-Host $message -ForegroundColor Yellow
                        $removeObj = New-Object System.Object
                        $removeObj | Add-Member -type NoteProperty -name FriendlyName -value $FriendlyName
                        $removeObj | Add-Member -type NoteProperty -name HWID -value $HWID
                        $removeObj | Add-Member -type NoteProperty -name InstallState -value $InstallState
                        $removeObj | Add-Member -type NoteProperty -name Class -value $Class
                        $removeArray += @($removeObj)
                        if([Win32.SetupApi]::SetupDiRemoveDevice($devs, [ref]$devInfo)){
                            Write-Host "Removed device $FriendlyName"  -ForegroundColor Green
                        } else {
                            Write-Host "Failed to remove device $FriendlyName" -ForegroundColor Red
                        }
                    } else {
                        Write-Host "OK, skipped" -ForegroundColor Yellow
                    }
                } else {
                    write-host "Filter matched. Skipping $FriendlyName" -ForegroundColor Yellow
                }
            }
        }
        $devcount++
    }

    #output objects so you can take the output from the script
    if ($listDevicesOnly) {
        $allDevices = $array | sort -Property FriendlyName
        $filteredDevices = Filter-Devices -Devices $allDevices
        $filteredDevices | ft
        write-host "Total devices found                : $($allDevices.count)"
        write-host "Total filtered devices found       : $($filteredDevices.count)"
        $ghostDevices = Get-Ghost-Devices -Devices $array
        $filteredGhostDevices = Filter-Devices -Devices $ghostDevices
        write-host "Total ghost devices found          : $($ghostDevices.count)"
        write-host "Total filtered ghost devices found : $($filteredGhostDevices.count)"
        return $filteredDevices | out-null
    }

    if ($listGhostDevicesOnly) {
        $ghostDevices = Get-Ghost-Devices -Devices $array
        $filteredGhostDevices = Filter-Devices -Devices $ghostDevices
        $filteredGhostDevices | ft
        write-host "Total ghost devices found           : $($ghostDevices.count)"
        write-host "Total filtered ghost devices found  : $($filteredGhostDevices.count)"
        return $filteredGhostDevices | out-null
    }

    if ($removeDevices -eq $true) {
        write-host "Removed devices:"
        $removeArray  | sort -Property FriendlyName | ft
        write-host "Total removed devices     : $($removeArray.count)"
        return $removeArray | out-null
    }
} #End Function

### End

### remove server manager from startup for current user
New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x1" –Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWORD -Value "0x1" -Force

IF (Get-process "servermanager" -ErrorAction SilentlyContinue) {

    Stop-Process -name servermanager -Force -ErrorAction SilentlyContinue
}

write-host "Collecting existing IP info" -ForegroundColor cyan

IF (-not(test-path "C:\Admin\ExistingIP.csv")) {

    $ExistingStaticIP = @(Get-NetAdapter | Where-Object {($_.Status -eq "UP") -and ($_.InterfaceDescription -like "*Hyper-V Network Adapter*")} | `
    Get-NetIPConfiguration | Select-Object @{E={$_.IPv4Address.IPAddress};Name="IP"}, @{E={$_.DNSServer.ServerAddresses};Name="DNS"}, @{E={$_.IPv4DefaultGateway.Nexthop};Name="Gateway"})
 
    $ExistingStaticIPSubnet = @((Get-NetAdapter | Where-Object {($_.Status -eq "UP") -and ($_.InterfaceDescription -like "*Hyper-V Network Adapter*")} | `
    Get-NetIPAddress -AddressFamily IPv4) | Select-Object @{E={$_.PrefixLength};Name='Subnet'})

    $ExistingStaticIP | ForEach {$_ | Add-Member -MemberType NoteProperty -name Subnet -Value $ExistingStaticIPSubnet.Subnet}

    Write-CustomLog -ScriptLog $ScriptLog -Message "Full IP address info has been collected from source Hyper-V VM and saved here: 'C:\Admin\ExistingIP.csv' "  -Level INFO
    Write-CustomLog -ScriptLog $ScriptLog -Message "IP: $($ExistingStaticIP.IP) , Gateway: $($ExistingStaticIP.Gateway), DNS: $($ExistingStaticIP.DNS), Subnet: $($ExistingStaticIP.Subnet)" -level INFO    

    $ExistingStaticIP | Export-CSV -Path "C:\Admin\ExistingIP.csv" -NoTypeInformation -Force

    ## Create scheduled task for post V2V

    Write-CustomLog -ScriptLog $ScriptLog -Message "Creating scheduled task, and temp account that will auto-logon once the V2V operation is done"  -Level INFO

    Register-ScheduledTask -XML (Get-content "C:\Admin\Start-V2V.xml" | Out-String) -TaskName Start-V2V -Force   

    $Password =  convertTo-securestring "SECUREPWGOESHERE" -asplaintext -force
        
    IF (-not(Get-LocalUser | Where-Object {$_.Name -eq "V2V"})) {

        New-LocalUser "V2V" -Password $Password -FullName "V2V" -Description "temp account for converting from Hyper-V to ESXi"
        Add-LocalGroupMember -Group "Administrators" -Member "V2V"

    }

    Else {

        Write-host "user V2V already exists" -ForegroundColor Green

    }
    
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String
    Set-ItemProperty $RegistryPath 'AutoLogonCount' -Value "2" -Type String
    Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "V2V" -type String 
    Set-ItemProperty $RegistryPath 'DefaultPassword' -Value ([System.Net.NetworkCredential]::new("", $Password).Password)  -type String    

    Write-CustomLog -ScriptLog $ScriptLog -Message "Please gracefully power off the VM and run through the V2V process" -level INFO

    Stop-service -Name wuauserv
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    
    EXIT

}

<#
Else {

    Write-CustomLog -ScriptLog $ScriptLog -Message "no work to be done, please power off the VM and run the V2V process" -level INFO
    EXIT

}
#>

## Post V2V activities 
## Install VMware tools start

$VMT = Get-VMToolsInstalled

IF (($VMType -eq "VMware, Inc.") -and (-not($VMT))) {

    Write-CustomLog -ScriptLog $ScriptLog -Message "VMware type VM confirmed, starting install attempt of VMware tools" -Level INFO

    $VMTexe = Get-ChildItem c:\admin -Filter VMware-tools-*.exe | Select-Object -ExpandProperty FullName

    Write-CustomLog -ScriptLog $ScriptLog -Message "VMware type VM confirmed, starting install attempt of VMware tools" -Level INFO    

    Start-Process "$VMTexe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

    ### 3 - After the installation is finished, check to see if the 'VMTools' service enters the 'Running' state every 2 seconds for 10 seconds
    $Running = $false
    $iRepeat = 0

    while (-not$Running -and $iRepeat -lt 5) {      

      Write-CustomLog -ScriptLog $ScriptLog -Message "Pause for 2 seconds to check running state on VMware tools service" -Level INFO
      Start-Sleep -s 2
      $Service = Get-Service "VMTools" -ErrorAction SilentlyContinue
      $Servicestatus = $Service.Status

      if ($ServiceStatus -notlike "Running") {

        $iRepeat++

      }

      Else {

        $Running = $true

        Write-CustomLog -ScriptLog $ScriptLog -Message "VMware tools service found to be running state after first install attempt" -Level INFO
        
      }

    }
    ### 4 - If the service never enters the 'Running' state, re-install VMWare Tools
    if (-not$Running) {

      #Uninstall VMWare Tools
      Write-CustomLog -ScriptLog $ScriptLog -Message "Running un-install on first attempt of VMware tools install" -Level WARN

      IF (Get-VMToolsInstalled -eq "32") {
  
        $GUID = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName

      }

      Else {
  
        $GUID = (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName

      }

      ### 5 - Un-install VMWARe tools based on 32-bit/64-bit install GUIDs captured via Get-VMToolsIsInstalled function
  
      Start-Process -FilePath msiexec.exe -ArgumentList "/X $GUID /quiet /norestart" -Wait  

      Write-CustomLog -ScriptLog $ScriptLog -Message "Running re-install of VMware tools install" -Level INFO
    
      #Install VMWare Tools
      Start-Process "$VMTexe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

      ### 6 - Re-check again if VMTools service has been installed and is started

     Write-CustomLog -ScriptLog $ScriptLog -Message "Re-checking if VMTools service has been installed and is started" -Level INFO 
  
    $iRepeat = 0
    while (-not$Running -and $iRepeat -lt 5) {

        Start-Sleep -s 2
        $Service = Get-Service "VMTools" -ErrorAction SilentlyContinue
        $ServiceStatus = $Service.Status
    
        If ($ServiceStatus -notlike "Running") {

          $iRepeat++

        }

        Else {

          $Running = $true
          Write-CustomLog -ScriptLog $ScriptLog -Message "VMware tools service found to be running state after SECOND install attempt" -Level INFO
        
        }

      }

      ### 7 If after the reinstall, the service is still not running, this is a failed deployment

      IF (-not$Running) {
        Write-CustomLog -ScriptLog $ScriptLog -Message "VMWare Tools is still not installed correctly. The automated deployment will not process any further until VMWare Tools is installed" -Level ERROR
        EXIT

      }

    }

    ## Re-adding IP address   

    IF (test-path "C:\Admin\ExistingIP.csv") {

        Write-CustomLog -ScriptLog $ScriptLog -Message "Removing ghost network card" -Level INFO        

        Remove-GhostNICs -NarrowByFriendlyName "Microsoft Hyper-V Network Adapter" -Force

        $StaticIPFromCSV = Import-Csv "C:\Admin\ExistingIP.csv"

        Write-CustomLog -ScriptLog $ScriptLog -Message "Adding back previous static IP info" -Level INFO

        @((Get-NetAdapter | Where-Object {($_.Status -eq "UP") -and ($_.InterfaceDescription -like "*vmxnet*") -or ($_.InterfaceDescription -like "Intel(R)*")})) | `
        New-NetIPAddress -IPAddress $StaticIPFromCSV.IP -PrefixLength 24 -DefaultGateway $StaticIPFromCSV.Gateway

        @((Get-NetAdapter | Where-Object {($_.Status -eq "UP") -and ($_.InterfaceDescription -like "*vmxnet*") -or ($_.InterfaceDescription -like "Intel(R)*")})) | `
        Set-DnsClientServerAddress -ServerAddresses ($StaticIPFromCSV.DNS).Split("")[0], ($StaticIPFromCSV.DNS).Split("")[1]
        
        Get-ScheduledTask -TaskName Start-V2V -ErrorAction SilentlyContinue | Disable-ScheduledTask

        Write-CustomLog -ScriptLog $ScriptLog -Message "flush and re-register DNS and reboot in 30 seconds" -Level INFO
    
        ipconfig /flushdns
        ipconfig /registerdns

        Write-CustomLog -ScriptLog $ScriptLog -Message "Re-enabling windows update and removing V2V auto logon" -level INFO

        Set-Service -Name wuauserv -StarstupType Automatic -ErrorAction SilentlyContinue

        $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        Remove-ItemProperty $RegistryPath -Name 'AutoAdminLogon'
        Remove-ItemProperty $RegistryPath -Name 'AutoLogonCount'
        Remove-ItemProperty $RegistryPath -Name 'DefaultUsername'
        Remove-ItemProperty $RegistryPath -Name 'DefaultPassword'

        Write-CustomLog -ScriptLog $ScriptLog -Message "rebooting VM" -level INFO

        restart-computer -force

    }

    Else {

        Write-warning "Previous static IP info not recorded, script will exit"
        EXIT

    }

    ### End of script

} #If VMware VM type



