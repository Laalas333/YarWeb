rule MalwareDetection {
    meta:
        description = "Generic rule for SnakeKeylogger .exe malwares"
        author = "Group project"
    strings:
        $s0 = "lSystem.Resources.ResourceReader, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089#System.Resources.R" ascii
        $s1 = "aKveL.exe" fullword wide
        $s2 = "694F6B4A42" wide /* hex encoded string 'iOkJB' */
        $s3 = "aKveL.pdb" fullword ascii
        $s4 = "inputPassword" fullword wide
        $s5 = "get_WinFormAppConnectionString" fullword ascii
        $s6 = "lblPassword" fullword wide
        $s7 = "ffW9yKF1j" fullword ascii /* base64 encoded string '}or(]c' */
        $s8 = "inputDescription" fullword wide
        $s9 = "_DescriptionT" fullword ascii
        $s10 = "System.Windows.Forms.TreeNode" fullword wide
        $s11 = "WinFormApp.Properties.Settings.WinFormAppConnectionString" fullword wide
        $s12 = "get_MenuFunction" fullword ascii
        $s13 = "get_idParentMenu" fullword ascii
        $s14 = "get_menuType1" fullword ascii
        $s15 = "* F,M'T" fullword ascii
        $s16 = "getMenuType" fullword ascii
        $s17 = "logOutput" fullword wide
        $s18 = "get_MenuName" fullword ascii
        $s19 = "get_menuTypeName" fullword ascii
        $s20 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPADo" fullword ascii
        $s21 = "OrbOfEverything.exe" fullword wide
        $s22 = "OrbOfEverything.Game.Logic.Enemy" fullword ascii
        $s23 = "OrbOfEverything.Game.Logic.Player" fullword ascii
        $s24 = "OrbOfEverything.Game.Logic.Core" fullword ascii
        $s25 = "OrbOfEverything.Game.Logic.PowerUp" fullword ascii
        $s26 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
        $s27 = "targetDuration" fullword ascii
        $s28 = "MakeInvulnerable" fullword ascii
        $s29 = "IsVulnerable" fullword ascii
        $s30 = "MakeVulnerable" fullword ascii
        $s31 = "OrbOfEverything.GameDefeatDialog" fullword ascii
        $s32 = "GameDefeatDialog_FormClosed" fullword ascii
        $s33 = "get_enemyOrbInBlue" fullword ascii
        $s34 = "get_enemyOrbInPurple" fullword ascii
        $s35 = "OrbOfEverything.GameDefeatDialog.GameDefeatDialog.resources" fullword ascii
        $s36 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" fullword ascii
        $s37 = "OOEValueAnimator.FixedUpdate is running." fullword wide
        $s38 = "get_endColor" fullword ascii
        $s39 = "?System.Windows.Forms.Design.ParentControlDesigner,System.DesignqSystem.ComponentModel.Design.IDesigner, System, Version=4.0.0.0" ascii
        $s40 = "fSystem.Drawing.Icon, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3agSystem.Drawing.Point, Sy" ascii
        $s41 = "System.Windows.Forms.ImageListStreamer, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089P" ascii
        $s42 = "stem.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aBj" fullword ascii
        $s43 = "sHXPC.exe" fullword wide
        $s44 = "506D6A6541" wide /* hex encoded string 'PmjeA' */
        $s45 = ", Culture=neutral, PublicKeyToken=b77a5c561934e089" fullword ascii
        $s46 = "XMLFormEditor.XMLTreeDialog.resources" fullword ascii
        $s47 = "XMLControl2ControlDictionary.ContainsKey:" fullword wide
        $s48 = "XMLControl2ControlDictionary.ContainsKey(ctr):" fullword wide
        $s49 = "Cross.ico" fullword wide
        $s50 = "Down.ico" fullword wide
        $s51 = "DownLeft.ico" fullword wide
        $s52 = "DownRight.ico" fullword wide
        $s53 = "Left.ico" fullword wide
        $s54 = "Right.ico" fullword wide
        $s55 = "TDown.ico" fullword wide
        $s56 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" fullword ascii
        $s57 = "lfwhUWZlmFnGhDYPudAJ.exe" fullword wide
        $s58 = "get_encryptedPassword" fullword ascii
        $s59 = "SMTP Password" fullword wide
        $s60 = "Foxmail.exe" fullword wide
        $s61 = "\\GhostBrowser\\User Data\\Default\\Login Data" fullword wide
        $s62 = "\\mozglue.dll" fullword wide
        $s63 = " - keystroke Logs ID - " fullword wide
        $s64 = " - Passwords ID - " fullword wide
        $s65 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A667" wide
        $s66 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" fullword ascii
        $s67 = "\\Comodo\\Dragon\\User Data\\Default\\Login Data" fullword wide
        $s68 = "\\SnakeKeylogger" fullword wide
        $s69 = "\\SnakeKeylogger\\" fullword wide
        $s70 = "Key Content * : (?<after>.*)" fullword wide
        $s71 = "set_encryptedPassword" fullword ascii
        $s72 = "KeyLoggerEventArgsEventHandler" fullword ascii
        $s73 = "get_timePasswordChanged" fullword ascii
        $s74 = "KeyLoggerEventArgs" fullword ascii
        $s75 = "LumberRacer.exe" fullword wide
        $s76 = "SendKeyboardCommand" fullword ascii
        $s77 = "GetKeyCommands" fullword ascii
        $s78 = "set_CommandCount" fullword ascii
        $s79 = "<CommandCount>k__BackingField" fullword ascii
        $s80 = "get_AlgorithmConfig" fullword ascii
        $s81 = "GetCommandForLeaf" fullword ascii
        $s82 = "Telegram Lumberjack Racer - by @mehrandvd" fullword wide
        $s83 = "Lumber Racer - By Mehran DVD" fullword wide
        $s84 = "get_IsGameStarted" fullword ascii
        $s85 = "pictureBoxEye" fullword wide
        $s86 = "get_GrdidingSize" fullword ascii
        $s87 = "get_RequiredScore" fullword ascii
        $s88 = "pictureBoxEye_MouseClick" fullword ascii
        $s89 = "Want more than 400 scores!!!!!!??" fullword ascii
        $s90 = "GetColorDistance" fullword ascii
        $s91 = "btnStartEye_Click" fullword ascii
        $s92 = "pet.exe" fullword wide
        $s93 = "pet.FormLogin.resources" fullword ascii
        $s94 = "FormLogin" fullword wide
        $s95 = "lblLogin" fullword wide
        $s96 = "txtLogin" fullword wide
        $s97 = "btnLogin_Click" fullword ascii
        $s98 = "btnLogin" fullword wide
        $s99 = "SELECT login, senha FROM Funcionarios WHERE login = @login AND senha = @senha" fullword wide
        $s100 = "Login ou senha inv" fullword wide
        $s101 = "pbCliente" fullword wide /* base64 encoded string 'l)bz{^' */
        $s102 = "Data Source = (LocalDB)\\MSSQLLocalDB; AttachDbFilename=C:\\Programas\\pet\\pet\\DbPetshop1.mdf;Integrated Security = True" fullword wide
        $s103 = "@login" fullword wide
        $s104 = "textodecode" fullword ascii
        $s105 = "uxx, - )M" fullword ascii
        $s106 = "Nlog#sDw" fullword ascii
        $s107 = "InserirCliente" fullword wide
        $s108 = "textoencode" fullword ascii
        $s109 = "WinForm-SearchBox.exe" fullword wide
        $s110 = "get_displaytext" fullword ascii
        $s111 = "get_colname" fullword ascii
        $s112 = "displaytext" fullword wide
        $s113 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
        $s114 = "_x:\"t+" fullword ascii
        $s115 = "User Weight" fullword wide
        $s116 = "comboBox1_SelectedIndexChanged" fullword ascii
        $s117 = "Keyword:" fullword wide
        $s118 = "Edwardson" fullword ascii
        $s119 = "Rukhsana" fullword ascii
        $s120 = "Bolkvadze" fullword ascii
        $s121 = "Waldemar" fullword ascii
        $s122 = "Espinoza" fullword ascii
        $s123 = "17.0.0.0" fullword ascii
        $s124 = "Gouveia" fullword ascii
        $s125 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
    condition:
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )) or ( all of them )
}