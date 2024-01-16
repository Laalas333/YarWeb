rule MalwareDetection {
    meta:
        description = "Generic rule for Loki .exe malwares"
        author = "Group project"
    strings:
        $s0 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
        $s1 = "UXlsZakz.exe" fullword wide
        $s2 = "ExecuteButton" fullword wide
        $s3 = "ExecuteButton_Click" fullword ascii
        $s4 = "ProcessOneLine" fullword ascii
        $s5 = "UXlsZakz.pdb" fullword ascii
        $s6 = "PasswordTextbox" fullword wide
        $s7 = "StringCommandParameter" fullword ascii
        $s8 = "BASIC AUTH requires a password" fullword wide
        $s9 = "Executing ..." fullword wide
        $s10 = "HttpMethodComboBox" fullword wide
        $s11 = "get_tSCCgXXP" fullword ascii
        $s12 = "afterAt" fullword ascii
        $s13 = "7453434367585850%716562" fullword wide /* hex encoded string 'tSCCgXXPqeb' */
        $s14 = "MIME (Content Type)" fullword wide
        $s15 = "paramter" fullword ascii
        $s16 = "UsernameLabel" fullword wide
        $s17 = "MarkdownTableFormatter.Properties.Resources.resources" fullword ascii
        $s18 = "ServiceURLTextbox" fullword wide
        $s19 = "ServiceURLLabel" fullword wide
        $s20 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADP" fullword ascii
        $s21 = "HscA.exe" fullword wide
        $s22 = "HscA.pdb" fullword ascii
        $s23 = "GetFreeSquares" fullword ascii
        $s24 = "get_NoSolutions" fullword ascii
        $s25 = "get_Searching" fullword ascii
        $s26 = "* W|-{H" fullword ascii
        $s27 = "get_FoundSolutions" fullword ascii
        $s28 = "75444246%626F69" fullword wide /* hex encoded string 'uDBFboi' */
        $s29 = "*jRjCWRUNx" fullword ascii
        $s30 = "nQueensInput_KeyPress" fullword ascii
        $s31 = "16.0.0.0" fullword ascii
        $s32 = "Win Forms Collaboration" fullword wide
        $s33 = "get_uDBF" fullword ascii
        $s34 = "Eighter" fullword wide
        $s35 = "etna forma aplikacije" fullword wide
        $s36 = "label01" fullword wide
        $s37 = "get_QueenLocations" fullword ascii
        $s38 = "btnStudent7" fullword wide
        $s39 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" fullword ascii
        $s40 = "sCrypt32.dll" fullword wide
        $s41 = "SmtpPassword" fullword wide
        $s42 = "SMTP Password" fullword wide
        $s43 = "FtpPassword" fullword wide
        $s44 = "%s\\%s%i\\data\\settings\\ftpProfiles-j.jsd" fullword wide
        $s45 = "aPLib v1.01  -  the smaller the better :)" fullword ascii
        $s46 = "%s\\%s\\User Data\\Default\\Login Data" fullword wide
        $s47 = "%s%s\\Login Data" fullword wide
        $s48 = "%s%s\\Default\\Login Data" fullword wide
        $s49 = "%s\\32BitFtp.TMP" fullword wide
        $s50 = "%s\\GoFTP\\settings\\Connections.txt" fullword wide
        $s51 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword wide
        $s52 = "%s\\Mozilla\\SeaMonkey\\Profiles\\%s" fullword wide
        $s53 = "%s\\%s\\%s.exe" fullword wide
        $s54 = "More information: http://www.ibsensoftware.com/" fullword ascii
        $s55 = "%s\\nss3.dll" fullword wide
        $s56 = "PopPassword" fullword wide
        $s57 = "SmtpPort" fullword wide
        $s58 = "SmtpAccount" fullword wide
        $s59 = "MKiJ887777.exe" fullword wide
        $s60 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
        $s61 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
        $s62 = " Type Descriptor'" fullword ascii
        $s63 = " constructor or from DllMain." fullword ascii
        $s64 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
        $s65 = "XOQ.exS" fullword ascii
        $s66 = " Class Hierarchy Descriptor'" fullword ascii
        $s67 = " Base Class Descriptor at (" fullword ascii
        $s68 = " Complete Object Locator'" fullword ascii
        $s69 = "1CXm- " fullword ascii
        $s70 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
        $s71 = "MKiJ887777" fullword wide
        $s72 = "Broken pipe" fullword ascii /* Goodware String - occured 742 times */
        $s73 = "Permission denied" fullword ascii /* Goodware String - occured 823 times */
        $s74 = "c;XxiVu^-" fullword ascii
        $s75 = "SQKL4wp" fullword ascii
        $s76 = "L$PQSV" fullword ascii /* Goodware String - occured 1 times */
        $s77 = "CZBj>T]e];.n" fullword ascii
        $s78 = "9pMKrVn4" fullword ascii
    condition:
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )) or ( all of them )
}