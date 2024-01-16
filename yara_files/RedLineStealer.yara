rule MalwareDetection {
    meta:
        description = "Generic rule for RedLineStealer .exe malwares"
        author = "Group project"
    strings:
        $s0 = "user.config{0}\\FileZilla\\sitemanager.xmlcookies.sqlite\\Program Files (x86)\\configRoninWalletdisplayNamehost_key\\Electrum\\w" wide
        $s1 = "[^\\u0020-\\u007F]ProcessIdname_on_cardencrypted_valuehttps://ipinfo.io/ip%appdata%\\logins{0}\\FileZilla\\recentservers.xml%app" wide
        $s2 = "System.Security.Permissions.SecurityPermissionAttribute, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934" ascii
        $s3 = "DownloadAndExecuteUpdate" fullword ascii
        $s4 = "Happy.exe" fullword ascii
        $s5 = "egram.exe" fullword wide
        $s6 = "Implosions.exe" fullword wide
        $s7 = "System.Collections.Generic.IEnumerable<ScannedFile>.GetEnumerator" fullword ascii
        $s8 = "get_TaskProcessors" fullword ascii
        $s9 = "System.Collections.Generic.IEnumerator<ScannedFile>.get_Current" fullword ascii
        $s10 = "*autofillexpiraas21tion_yas21earffnbelfdoeiohenkjibnmadjiehjhajbProfilesTotal of RAMhttps://api.ip.sb/geoip%USERPEnvironmentROFI" wide
        $s11 = "get_encrypted_key" fullword ascii
        $s12 = "set_Processes" fullword ascii
        $s13 = "<Processes>k__BackingField" fullword ascii
        $s14 = "ITaskProcessor" fullword ascii
        $s15 = "System.Collections.Generic.IEnumerator<ScannedFile>.Current" fullword ascii
        $s16 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
        $s17 = "<TaskProcessors>k__BackingField" fullword ascii
        $s18 = "<Logins>k__BackingField" fullword ascii
        $s19 = "get_ScanGeckoBrowsersPaths" fullword ascii
        $s20 = "C:\\lugine\\wareguhilim\\moyakucodujap\\texajahuci\\takowir.pdb" fullword ascii
        $s21 = "jaxokitenimebi. Roza rezojimojila xucopet gexasefucihedo xilumoroj. Zujigobawufiy rabotivoge jigakeyemafu jojejiku gegitejoj. Re" ascii
        $s22 = "Ziyo mewulew bixinelujuya cotomot gihebiloleyu. Yoxevejobiv lat kuyo yosufereja. Zixasul jokujunaxod. Liw. Temajupawuzop dizafir" ascii
        $s23 = " Type Descriptor'" fullword ascii
        $s24 = " constructor or from DllMain." fullword ascii
        $s25 = "yucipefihaxonapuponotenujarunohi japujixitaxotiyir" fullword wide
        $s26 = "JJiruj roci logij rimi bucokuhofi temuciwebasuso yek mugarifodovuxah hozepu" fullword wide
        $s27 = "lejojegadocuzoyeg" fullword ascii
        $s28 = "limiwininoxujirexavuxuyabeba" fullword wide
        $s29 = "tesidoyekacolejodiyawetites" fullword wide
        $s30 = "xonimehakibihex" fullword wide
        $s31 = "wuworeyaze" fullword wide
        $s32 = "felewineri" fullword wide
        $s33 = "larebapudidirobibagaximibe" fullword wide
        $s34 = "SonarDoor" fullword wide
        $s35 = ":$:3:9:B:N:\\:b:n:t:" fullword ascii
        $s36 = "tepim yolunicewu cirun yadiwis liyowepuloxizo. Rufahobavogad. Gigiforop zupozis. Ban rikesoyirovixo. Gawefidepetanal yikokojizo." ascii
        $s37 = "ProductsVersion" fullword wide
        $s38 = "ProductionVersion" fullword wide
        $s39 = "WJawasubowa bepuyovunon fagebu palijugamezizu hun fitajedusihiy hicom liholotupol naroko" fullword wide
        $s40 = "srvcli.dll" fullword wide /* reversed goodware string 'lld.ilcvrs' */
        $s41 = "devrtl.dll" fullword wide /* reversed goodware string 'lld.ltrved' */
        $s42 = "dfscli.dll" fullword wide /* reversed goodware string 'lld.ilcsfd' */
        $s43 = "browcli.dll" fullword wide /* reversed goodware string 'lld.ilcworb' */
        $s44 = "linkinfo.dll" fullword wide /* reversed goodware string 'lld.ofniknil' */
        $s45 = "atl.dll" fullword wide /* reversed goodware string 'lld.lta' */
        $s46 = "gCrypt32.dll" fullword wide
        $s47 = "SSPICLI.DLL" fullword wide
        $s48 = "UXTheme.dll" fullword wide
        $s49 = "oleaccrc.dll" fullword wide
        $s50 = "dnsapi.DLL" fullword wide
        $s51 = "iphlpapi.DLL" fullword wide
        $s52 = "WINNSI.DLL" fullword wide
        $s53 = "sfxzip.exe" fullword ascii
        $s54 = "Cannot create folder %sHChecksum error in the encrypted file %s. Corrupt file or wrong password." fullword wide
        $s55 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxzip32\\Release\\sfxzip.pdb" fullword ascii
        $s56 = "Setup=PO.exe" fullword ascii
        $s57 = ";The comment below contains SFX script commands" fullword ascii
        $s58 = "$GETPASSWORD1:IDC_PASSWORDENTER" fullword ascii
        $s59 = "$GETPASSWORD1:IDOK" fullword ascii
        $s60 = "Fusce in sapien lobortis eros faucibus pharetra eu a nibh. Suspendisse tempus at magna at eleifend. Maecenas mollis dolor ipsum," ascii
        $s61 = "Phasellus ac erat pretium mi gravida aliquet. Integer at tellus aliquam nunc tempus venenatis. Curabitur ut commodo odio, a tinc" ascii
        $s62 = "* kQyr" fullword ascii
        $s63 = "acilisis viverra rhoncus. Aenean sed auctor est. Nullam sollicitudin erat orci, vel dapibus ex convallis at. Aenean in sollicitu" ascii
        $s64 = "tqzituo" fullword ascii
        $s65 = "nsstqop" fullword ascii
        $s66 = "vtuzotq" fullword ascii
        $s67 = "tuoqtwp" fullword ascii
        $s68 = "qjsoztu" fullword ascii
        $s69 = "nwozswj" fullword ascii
        $s70 = "tpzoztu" fullword ascii
        $s71 = "tvstpzoztu" fullword ascii
        $s72 = "tsoztup" fullword ascii
        $s73 = "qzsoztu" fullword ascii
        $s74 = " vel cursus justo elementum vel. Curabitur commodo sed lorem in auctor. Curabitur at diam lorem. Nunc nulla purus, consequat sus" ascii
        $s75 = "din mi, interdum volutpat dolor. Integer porta, dolor vitae molestie blandit, velit sapien eleifend lacus, sit amet pellentesque" ascii
    condition:
         ( uint16(0) == 0x5a4d and filesize < 3000KB and ( 8 of them )) or ( all of them )
}