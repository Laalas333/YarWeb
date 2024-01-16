rule MalwareDetection {
    meta:
        description = "Generic rule for AgentTesla .exe malwares"
        author = "Group project"
    strings:
        $s0 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
        $s1 = "OUIkm.exe" fullword wide
        $s2 = "6C546A4F59" wide /* hex encoded string 'lTjOY' */
        $s3 = "OUIkm.pdb" fullword ascii
        $s4 = "get_WinFormAppConnectionString" fullword ascii
        $s5 = "lblPassword" fullword wide
        $s6 = "inputPassword" fullword wide
        $s7 = "inputDescription" fullword wide
        $s8 = "_DescriptionT" fullword ascii
        $s9 = "System.Windows.Forms.TreeNode" fullword wide
        $s10 = "WinFormApp.Properties.Settings.WinFormAppConnectionString" fullword wide
        $s11 = "get_MenuTransact" fullword ascii
        $s12 = "get_NewWindow" fullword ascii
        $s13 = "get_MenuName" fullword ascii
        $s14 = "logOutput" fullword wide
        $s15 = "get_idParentMenu" fullword ascii
        $s16 = "get_MenuFunction" fullword ascii
        $s17 = "menuTree_DragEnter" fullword ascii
        $s18 = "get_menuTypeName" fullword ascii
        $s19 = "get_MenuOrder" fullword ascii
        $s20 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADh" fullword ascii
        $s21 = "OCWsy.exe" fullword wide
        $s22 = "get_passWord" fullword ascii
        $s23 = "7245557758" wide /* hex encoded string 'rEUwX' */
        $s24 = "select * from Account where UserName = '{0}' and PassWord = '{1}'" fullword wide
        $s25 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
        $s26 = "OCWsy.pdb" fullword ascii
        $s27 = "set_passWord" fullword ascii
        $s28 = "AccountId" fullword wide
        $s29 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
        $s30 = "get_AssemblyDescription" fullword ascii
        $s31 = "EditEmployee" fullword ascii
        $s32 = "DonNha.DTO" fullword ascii
        $s33 = "DonNha.SSA" fullword ascii
        $s34 = "get_FoodName" fullword ascii
        $s35 = "get_Quantity" fullword ascii
        $s36 = "getOrderId" fullword ascii
        $s37 = "get_EmployeeName" fullword ascii
        $s38 = "get_TotalPrice" fullword ascii
        $s39 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADs" fullword ascii
        $s40 = "Becml.exe" fullword wide
        $s41 = "5355557257" wide /* hex encoded string 'SUUrW' */
        $s42 = "Connect attempt failed; Handshake already in progress" fullword wide
        $s43 = "m_executeFlushSendQueue" fullword ascii
        $s44 = "5asyncWinForms.Service+<RunAsyncMathWrappedInTask>d__2" fullword ascii
        $s45 = "2asyncWinForms.Service+<RunMathInternallyAsync>d__8" fullword ascii
        $s46 = "TEMPER5" fullword ascii
        $s47 = "<runDialog>5__2" fullword ascii
        $s48 = "TEMPER3" fullword ascii
        $s49 = "<RunDialog>b__0" fullword ascii
        $s50 = "TEMPER4" fullword ascii
        $s51 = "TEMPER2" fullword ascii
        $s52 = "TEMPER6" fullword ascii
        $s53 = "TEMPER1" fullword ascii
        $s54 = "Received Connect, but we're not accepting incoming connections!" fullword wide
        $s55 = ":1\"><NewRemoteHost></NewRemoteHost><NewExternalPort>" fullword wide
        $s56 = "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:" fullword wide
        $s57 = ":1\"></u:GetExternalIPAddress>" fullword wide
        $s58 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADC" fullword ascii
        $s59 = "mqbHE.exe" fullword wide
        $s60 = "4E68746450" wide /* hex encoded string 'NhtdP' */
        $s61 = "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:schemas-upnp-org:service:" fullword wide
    condition:
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )) or ( all of them )
}