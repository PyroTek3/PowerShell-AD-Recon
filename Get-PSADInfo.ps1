#function Get-PSADInfo
#{

<#
.SYNOPSIS
This script is used to gather information on the Active Directory environment.

PowerSploit Function: Get-PSADInfo.ps1
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Version: 0.3

.DESCRIPTION
This script is used to gather information on the Active Directory environment.

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

Currently, the script performs the following actions:
    * Identifies the current AD forest and lists Forest Mode & Forest FSMOs.
    * Enumerates all domain details (including child domains).
    * Domain details (for all domains including forest root) include:
        - Netbios Name
        - Domain SID
        - Domain Mode
        - Domain krbtgt Last Password Set Date
        - Domain FSMOs
        - Domain Password Policy
        - Child Domains
        - Domain Service Accounts, inlcudes AccountName, DisplayName, PwdLastSet,LastLogon,Description
    * Identifies AD & Exchange schema versions
    * Enumerates AD Sites and provides report including Subnet & server data
    * Generates report of all AD Forest DCs including DC FQDN, Domain, IP, Site, Roles, & OS.


.PARAMETER AAAA
This script is used to gather information on the Active Directory environment.

.EXAMPLE
Get-PSADInfo
This script is used to gather information on the Active Directory environment.

.NOTES
This script is used to gather information on the Active Directory environment.

.LINK

#>
Param
    (

    )

# Get RootDSE Info
$rootDSE = [adsi]"LDAP://rootDSE"
$rootDSEconfigurationNamingContext = $rootDSE.configurationNamingContext
$rootDSEcurrentTime = $rootDSE.currentTime  ## Convert
$rootDSEdefaultNamingContext = $rootDSE.defaultNamingContext
$rootDSEdnsHostName = $rootDSE.dnsHostName
$rootDSEdomainControllerFunctionality = $rootDSE.domainControllerFunctionality
$rootDSEdomainFunctionality = $rootDSE.domainFunctionality  ## Convert
$rootDSEdsServiceName = $rootDSE.dsServiceName
$rootDSEforestFunctionality = $rootDSE.forestFunctionality  ## Convert
$rootDSEhighestCommittedUSN = $rootDSE.highestCommittedUSN
$rootDSEisGlobalCatalogReady = $rootDSE.isGlobalCatalogReady
$rootDSEisSynchronized = $rootDSE.isSynchronized
$rootDSEldapServiceName = $rootDSE.ldapServiceName
$rootDSEnamingContexts = $rootDSE.namingContexts
$rootDSErootDomainNamingContext = $rootDSE.rootDomainNamingContext
$rootDSEschemaNamingContext = $rootDSE.schemaNamingContext
$rootDSEserverName = $rootDSE.serverName
$rootDSEsubschemaSubentry = $rootDSE.subschemaSubentry
$rootDSEsupportedCapabilities = $rootDSE.supportedCapabilities
$rootDSEsupportedControl = $rootDSE.supportedControl
$rootDSEsupportedLDAPPolicies = $rootDSE.supportedLDAPPolicies
$rootDSEsupportedLDAPVersion = $rootDSE.supportedLDAPVersion
$rootDSEsupportedSASLMechanisms = $rootDSE.supportedSASLMechanisms

$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfoName = $ADForestInfo.Name
$ADForestInfoSites = $ADForestInfo.Sites
$ADForestInfoGlobalCatalogs = $ADForestInfo.GlobalCatalogs
$ADForestInfoApplicationPartitions = $ADForestInfo.ApplicationPartitions
$ADForestInfoForestMode = $ADForestInfo.ForestMode
$ADForestInfoSchema = $ADForestInfo.Schema
$ADForestInfoSchemaRoleOwner = $ADForestInfo.SchemaRoleOwner
$ADForestInfoNamingRoleOwner = $ADForestInfo.NamingRoleOwner
$ADForestInfoRootDomain = $ADForestInfo.RootDomain

$ADDomainInfo = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$ADDomainInfoName = $ADDomainInfo.Name
$ADDomainInfoForest = $ADDomainInfo.Forest
$ADDomainInfoDomainControllers = $ADDomainInfo.DomainControllers
$ADDomainInfoChildren = $ADDomainInfo.Children
$ADDomainInfoDomainMode = $ADDomainInfo.DomainMode
$ADDomainInfoParent = $ADDomainInfo.Parent
$ADDomainInfoPdcRoleOwner = $ADDomainInfo.PdcRoleOwner
$ADDomainInfoRidRoleOwner = $ADDomainInfo.RidRoleOwner
$ADDomainInfoInfrastructureRoleOwner = $ADDomainInfo.InfrastructureRoleOwner

$LocalSiteInfo = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()

$ADForestDomains = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).domains

<#
#######################################
# IN PROGRESS - AD Instantiation Date #
#######################################
#$ADForestInstatiationDate = Get-ADObject -SearchBase (Get-ADForest).PartitionsContainer `
#-LDAPFilter "(&(objectClass=crossRef)(systemFlags=3))" `
#-Property dnsRoot, nETBIOSName, whenCreated | Sort-Object whenCreated | Format-Table dnsRoot, nETBIOSName, whenCreated -AutoSize

$ADForestPartitionsContainer = "CN=Partitions," + $rootDSEconfigurationNamingContext

$ADSISearcherFID = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$ADSISearcherFID.SearchRoot = "LDAP://CN=$ADForestPartitionsContainer"
$ADSISearcherFID.PageSize = 500
$ADSISearcherFID.Filter = "(&(objectClass=crossRef)(systemFlags=3))"
$ADForestInstatiationDateResults = $ADSISearcherFID.FindOne()

Write-Output "AD Forest Instatiation Date: $ADForestInstatiationDate"

#>

$ADSISearcher = New-Object System.DirectoryServices.DirectorySearcher 
$ADSISearcher.SearchScope = "subtree" 
$ADSISearcher.PropertiesToLoad.Add("nETBIOSName") > $Null 
$ADSISearcher.SearchRoot = "LDAP://$ADForestPartitionsContainer" 

Write-Output "$ADForestInfoName Forest Information: "
Write-Output "===================================== "
Write-Output " Forest Mode: $ADForestInfoForestMode "    
Write-Output " Forest FSMOs: "
Write-Output "  * Schema Master: $ADForestInfoSchemaRoleOwner  "
Write-Output "  * Domain Naming Master: $ADForestInfoNamingRoleOwner  "
Write-Output " "


[array]$ALLADForestDomainControllers = $Null
ForEach ($ADForestDomainsItem in $ADForestDomains)
    {
        $AllADUServiceAccountReport = $Null
        $ADForestDomainsItemName = $ADForestDomainsItem.Name
        $ADForestDomainsItemForest = $ADForestDomainsItem.Forest
        $ADForestDomainsItemDomainMode = $ADForestDomainsItem.DomainMode
        $ADForestDomainsItemPdcRoleOwner = $ADForestDomainsItem.PdcRoleOwner
        $ADForestDomainsItemRidRoleOwner  = $ADForestDomainsItem.RidRoleOwner 
        $ADForestDomainsItemInfrastructureRoleOwner = $ADForestDomainsItem.InfrastructureRoleOwner
        $ADForestDomainsItemChildren = $ADForestDomainsItem.Children

        [array]$ALLADForestDomainControllers += $ADForestDomainsItem.DomainControllers

        $DomainDetail = [ADSI]"LDAP://$ADForestDomainsItemName"
        $DomainDetailmaxPwdAgeValue = $DomainDetail.maxPwdAge.Value
        $DomainDetailminPwdAgeValue = $DomainDetail.minPwdAge.Value
        $DomainDetailmaxPwdAgeInt64 = $DomainDetail.ConvertLargeIntegerToInt64($DomainDetailmaxPwdAgeValue)
        $DomainDetailminPwdAgeInt64 = $DomainDetail.ConvertLargeIntegerToInt64($DomainDetailminPwdAgeValue)

        $MaxPwdAge = -$DomainDetailmaxPwdAgeInt64/(600000000 * 1440)
        $MinPwdAge = -$DomainDetailminPwdAgeInt64/(600000000 * 1440) 

        $DomainDetailminPwdLength = $DomainDetail.minPwdLength
        $DomainDetailpwdHistoryLength = $DomainDetail.pwdHistoryLength
        $DomainDetaildistinguishedName = $DomainDetail.distinguishedName
        $DomainDetailrIDManagerReference = $DomainDetail.rIDManagerReference

        $DomainDetailSID = (New-Object System.Security.Principal.SecurityIdentifier($DomainDetail.objectSid[0], 0)).Value

        $ADForestDomainsDN = "DC=" + $ADForestDomainsItemName -Replace("\.",',DC=') 
        $ADSISearcher.Filter = "(nCName=$ADForestDomainsDN)" 
        $ADForestDomainsItemNetBIOSName = ($ADSISearcher.FindOne()).Properties.Item("nETBIOSName") 

        $ADUserKRBSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
        $ADUserKRBSearch.SearchRoot = "LDAP://$ADForestDomainsDN"
        $ADUserKRBSearch.PageSize = 500
        $ADUserKRBSearch.Filter = "(&(objectCategory=User)(name=krbtgt))"
        $KRBADInfo = $ADUserKRBSearch.FindAll()
        
        [string]$KRBADInfopwdlastsetInt8 = $KRBADInfo.Properties.pwdlastset
        $KRBADInfopwdlastset = [DateTime]::FromFileTimeutc($KRBADInfopwdlastsetInt8)

        $ADUServiceAccountSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
        $ADUServiceAccountSearch.SearchRoot = "LDAP://$ADForestDomainsDN"
        $ADUServiceAccountSearch.PageSize = 500
        $ADUServiceAccountSearch.Filter = "(&(objectCategory=User)(name=*svc*))"
        [array]$ADUServiceAccountArray = $ADUServiceAccountSearch.FindAll()

        ForEach ($ADUServiceAccountArrayItem in $ADUServiceAccountArray)
            {
                $ADUServiceAccountArrayItemSAMAccountName = $ADUServiceAccountArrayItem.Properties.samaccountname
                $ADUServiceAccountArrayItemDisplayName = $ADUServiceAccountArrayItem.Properties.displayname
                $ADUServiceAccountArrayItemSAMAccountDescription = $ADUServiceAccountArrayItem.Properties.description
                [string]$ADUServiceAccountItemPwdLastSetInt8 = $ADUServiceAccountArrayItem.Properties.pwdlastset
                $ADUServiceAccountItemPwdLastSet = [DateTime]::FromFileTimeutc($ADUServiceAccountItemPwdLastSetInt8)
                [string]$ADUServiceAccountItemLastLogonTimestampInt8 = $ADUServiceAccountArrayItem.Properties.lastlogontimestamp
                $ADUServiceAccountItemLastLogonTimestamp = [DateTime]::FromFileTimeutc($ADUServiceAccountItemLastLogonTimestampInt8)
                
                $ADUServiceAccountReport = New-Object -TypeName PSObject 
                $ADUServiceAccountReport | Add-Member -MemberType NoteProperty -Name AccountName -Value $ADUServiceAccountArrayItemSAMAccountName 
                $ADUServiceAccountReport | Add-Member -MemberType NoteProperty -Name DisplayName -Value $ADUServiceAccountArrayItemDisplayName 
                $ADUServiceAccountReport | Add-Member -MemberType NoteProperty -Name PwdLastSet -Value $ADUServiceAccountItemPwdLastSet 
                $ADUServiceAccountReport | Add-Member -MemberType NoteProperty -Name LastLogon -Value $ADUServiceAccountItemLastLogonTimestamp 
                $ADUServiceAccountReport | Add-Member -MemberType NoteProperty -Name Description -Value $ADUServiceAccountArrayItemSAMAccountDescription 

                [array] $AllADUServiceAccountReport += $ADUServiceAccountReport
            }
        
        Write-Output "$ADForestDomainsItemName Domain Information: "
        Write-Output "============================================== "
        Write-Output " Forest name: $ADForestDomainsItemForest " 
        Write-Output " "
        Write-Output " Netbios name: $ADForestDomainsItemNetBIOSName " 
        Write-Output " Domain SID: $DomainDetailSID "
        Write-Output " Domain Mode: $ADForestDomainsItemDomainMode "
        Write-Output " "
        Write-Output " krbtgt Last Password Set Date: $KRBADInfopwdlastset "
        Write-Output " "
        Write-Output " Domain FSMOs: "
        Write-Output "  * PDC Emulator: $ADForestDomainsItemPdcRoleOwner "
        Write-Output "  * RID Master: $ADForestDomainsItemRidRoleOwner "
        Write-Output "  * Infrastructure Master: $ADForestDomainsItemInfrastructureRoleOwner "
        Write-Output " "
        Write-Output " Password Policy:  "
        Write-Output "  * Max Password Age: $MaxPwdAge days"
        Write-Output "  * Min Password Age: $MinPwdAge days"
        Write-Output "  * Password History: $DomainDetailpwdHistoryLength "
        Write-Output "  * Min Password Length: $DomainDetailminPwdLength "
        Write-Output " "
        Write-Output " Child Domains: " 
        ForEach ($ADForestDomainsItemChildrenItem in $ADForestDomainsItemChildren)
            { 
                $ADForestDomainsItemChildrenItemName = $ADForestDomainsItemChildrenItem.Name
                Write-Output "  * $ADForestDomainsItemChildrenItemName"  
            }
        Write-Output " "
        Write-Output " Domain Service Accounts (*svc*): " 
        $AllADUServiceAccountReport | Sort-Object PwdLastSet | Format-Table -AutoSize 
        Write-Output " "
    }

# Get AD and Exchange Schema version
Write-Verbose "Create Schema Version hashtable `r "
$SchemaVersionTable = 
@{ 
    "13" = "Windows 2000 Schema" ; 
    "30" = "Windows 2003 Schema"; 
    "31" = "Windows 2003 R2 Schema" ;
    "39" = "Windows 2008 BETA Schema" ;
    "44" = "Windows 2008 Schema" ; 
    "47" = "Windows 2008 R2 Schema" ; 
    "51" = "Windows Server 8 Developer Preview Schema" ;
    "52" = "Windows Server 8 BETA Schema" ;
    "56" = "Windows Server 2012 Schema" ;
    "69" = "Windows Server 2012 R2 Schema" ;

    "4397"  = "Exchange 2000 RTM Schema" ; 
    "4406"  = "Exchange 2000 SP3 Schema" ;
    "6870"  = "Exchange 2003 RTM Schema" ; 
    "6936"  = "Exchange 2003 SP3 Schema" ; 
    "10637"  = "Exchange 2007 RTM Schema" ;
    "11116"  = "Exchange 2007 RTM Schema" ; 
    "14622"  = "Exchange 2007 SP2 & Exchange 2010 RTM Schema" ; 
    "14625"  = "Exchange 2007 SP3 Schema" ;
    "14726" = "Exchange 2010 SP1 Schema" ;
    "14732" = "Exchange 2010 SP2 Schema" ;
    "14734" = "Exchange 2010 SP3 Schema" ;
    "15137" = "Exchange 2013 RTM Schema" ;
    "15254" = "Exchange 2013 CU1 Schema" ;
    "15281" = "Exchange 2013 CU2 Schema" ;
    "15283" = "Exchange 2013 CU3 Schema" ;
    "15292" = "Exchange 2013 SP1/CU4 Schema" ;
    "15300" = "Exchange 2013 CU5 Schema" ;
    "15303" = "Exchange 2013 CU6 Schema" 
 }

Write-Verbose "Get Exchange Forest Prep Version"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEExchangerangeUpper = ([ADSI]"LDAP://CN=ms-Exch-Schema-Version-Pt,CN=Schema,CN=Configuration,$RootDSE").rangeUpper
$RootDSEExchangeobjectVersion =([ADSI]"LDAP://cn=<ExhangeOrg>,cn=Microsoft Exchange,cn=Services,cn=Configuration,$RootDSE").objectVersion
$ExchangeSchemaVersionName = $SchemaVersionTable.Get_Item("$RootDSEExchangerangeUpper")
Write-Output "The current Exchange Schema Version is $RootDSEExchangerangeUpper which is $ExchangeSchemaVersionName `r "
Write-Output "  `r "

Write-Verbose "Get AD Forest Prep Version"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEADObjectVersion =([ADSI]"LDAP://$rootDSEschemaNamingContext").objectVersion
$ADSchemaVersionName = $SchemaVersionTable.Get_Item("$RootDSEADObjectVersion")
Write-Output "The current AD Schema Version is $RootDSEADObjectVersion which is $ADSchemaVersionName `r "
Write-Output "  `r "

# Get Tombstone Setting
Write-Verbose "Get Tombstone Setting `r"
$RootDSE= ([ADSI]"").distinguishedName
$RootDSEADTombstoneLifetime =([ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$rootDSEconfigurationNamingContext")
$TombstoneLifetime = $RootDSEADTombstoneLifetime.tombstoneLifetime
Write-Output "Active Directory's Tombstone Lifetime is set to $TombstoneLifetime days `r "

# Get AD Site List
Write-Verbose "Get AD Site List `r"
$ADSites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites 
[int]$ADSitesCount = $ADSites.Count
Write-Output "There are $ADSitesCount AD Sites `r"

Write-Output "Processing AD Site & Subnet data "
$AllADSiteSubnets = $Null
$AllADSiteReport = $Null

Write-Output "AD Forest Site & Subnet Report:"
Write-Output "==============================="
ForEach ($ADSitesItem in $ADSites)
    {
        $ADSitesItemDomains = $Null
        $ADSitesItemSubnets = $Null
        $ADSitesItemServers = $Null
        $ADSitesItemAdjacentSites = $Null
        $ADSitesItemSiteLinks = $Null
                
        $ADSitesItemName = $ADSitesItem.Name
        [array]$ADSitesItemDomainArray = $ADSitesItem.Domains
        [array]$ADSitesItemSubnetArray = $ADSitesItem.Subnets
        [array]$ADSitesItemServerArray = $ADSitesItem.Servers
        [array]$ADSitesItemAdjacentSiteArray = $ADSitesItem.AdjacentSites
        [array]$ADSitesItemSiteLinkArray = $ADSitesItem.SiteLinks

        ForEach ($ADSitesItemDomainArrayItem in $ADSitesItemDomainArray) 
            { [string]$ADSitesItemDomains += "$ADSitesItemDomainArrayItem;" }
        TRY { $ADSitesItemDomains = $ADSitesItemDomains.Substring(0,$ADSitesItemDomains.Length-1) }
            CATCH {}
                
        ForEach ($ADSitesItemSubnetArrayItem in $ADSitesItemSubnetArray) 
            { 
                [string]$ADSitesItemSubnets += "$ADSitesItemSubnetArrayItem;"
                [array]$AllADSiteSubnets += $ADSitesItemSubnetArrayItem
            }
        TRY { $ADSitesItemSubnets = $ADSitesItemSubnets.Substring(0,$ADSitesItemSubnets.Length-1) }
            CATCH {}
                
        ForEach ($ADSitesItemServerArrayItem in $ADSitesItemServerArray) 
            { [string]$ADSitesItemServers += "$ADSitesItemServerArrayItem;" }
        TRY { $ADSitesItemServers = $ADSitesItemServers.Substring(0,$ADSitesItemServers.Length-1) }
            CATCH {}
                
        ForEach ($ADSitesItemAdjacentSiteArrayItem in $ADSitesItemAdjacentSiteArray) 
            { [string]$ADSitesItemAdjacentSites += "$ADSitesItemAdjacentSiteArrayItem;" }
        TRY { $ADSitesItemAdjacentSites = $ADSitesItemAdjacentSites.Substring(0,$ADSitesItemAdjacentSites.Length-1) }
            CATCH {} 
                
        ForEach ($ADSitesItemSiteLinkArrayItem in $ADSitesItemSiteLinkArray) 
            { [string]$ADSitesItemSiteLinks += "$ADSitesItemSiteLinkArrayItem;" }
        TRY { $ADSitesItemSiteLinks = $ADSitesItemSiteLinks.Substring(0,$ADSitesItemSiteLinks.Length-1) } 
            CATCH {}                  

        IF ($ADSitesItem.IntraSiteReplicationSchedule) { [switch]$ADSitesItemIntraSiteReplicationSchedule = $True }
        ELSE { [switch]$ADSitesItemIntraSiteReplicationSchedule = $False }

        $ADSiteReport = New-Object -TypeName PSObject 
        $ADSiteReport | Add-Member -MemberType NoteProperty -Name SiteName -Value $ADSitesItemName 
        $ADSiteReport | Add-Member -MemberType NoteProperty -Name Domains -Value $ADSitesItemDomains 
        $ADSiteReport | Add-Member -MemberType NoteProperty -Name Subnets -Value $ADSitesItemSubnets 
        $ADSiteReport | Add-Member -MemberType NoteProperty -Name Servers -Value $ADSitesItemServers 
        # $ADSiteReport | Add-Member -MemberType NoteProperty -Name AdjacentSites -Value $ADSitesItemAdjacentSites 
        $ADSiteReport | Add-Member -MemberType NoteProperty -Name SiteLinks -Value $ADSitesItemSiteLinks 
        # $ADSiteReport | Add-Member -MemberType NoteProperty -Name SiteSchedule -Value $ADSitesItemIntraSiteReplicationSchedule 

        [array]$AllADSiteReport += $ADSiteReport
    }

$AllADSiteReport | sort-object SiteName | format-table -AutoSize

$AllADSiteSubnetsCount = $AllADSiteSubnets.Count
Write-Output "There are $AllADSiteSubnetsCount subnets configured in Active Directory"
$AllADSiteSubnets 
Write-Output ""

[int]$ALLADForestDomainControllersCount = $ALLADForestDomainControllers.Count
Write-Output "Discovered $ALLADForestDomainControllersCount Domain Controllers in the AD Forest $ADForestInfoName "

Write-Output "AD Forest Domain Controller Report:"
Write-Output "==================================="

$AllADDomainControllerReport = $Null
ForEach ($ALLADForestDomainControllersItem in $ALLADForestDomainControllers)
    {
        $ALLADForestDomainControllersItemName = $ALLADForestDomainControllersItem.Name
        $ALLADForestDomainControllersItemOSVersion = $ALLADForestDomainControllersItem.OSVersion
        [array]$ALLADForestDomainControllersItemRoleArray = $ALLADForestDomainControllersItem.Roles
        $ALLADForestDomainControllersItemDomain = $ALLADForestDomainControllersItem.Domain
        $ALLADForestDomainControllersItemIPAddress = $ALLADForestDomainControllersItem.IPAddress
        $ALLADForestDomainControllersItemSiteName = $ALLADForestDomainControllersItem.SiteName
        [array]$ALLADForestDomainControllersItemPartitionArray = $ALLADForestDomainControllersItem.Partitions

        $ALLADForestDomainControllersItemRoles = $Null
        ForEach ($ALLADForestDomainControllersItemRoleArrayItem in $ALLADForestDomainControllersItemRoleArray)
            { [string]$ALLADForestDomainControllersItemRoles += $ALLADForestDomainControllersItemRoleArrayItem }
        
        $ALLADForestDomainControllersItemPartitions = $Null
        ForEach ($ALLADForestDomainControllersItemPartitionArrayItem in $ALLADForestDomainControllersItemPartitionArray)
            { [string]$ALLADForestDomainControllersItemPartitions += $ALLADForestDomainControllersItemPartitionArrayItem }

        $ComputerADInfoShortOS = $Null
        $ComputerADInfoShortOSArray = $ALLADForestDomainControllersItemOSVersion -split(" ")
        ForEach ($ComputerADInfoShortOSArrayItem in $ComputerADInfoShortOSArray ) 
            {
                IF ($ComputerADInfoShortOSArrayItem -eq "Windows")
                    { [string] $ComputerADInfoShortOS += "Win" }
                                
                IF ($ComputerADInfoShortOSArrayItem -eq "Server")
                    { }

                IF ($ComputerADInfoShortOSArrayItem -match "\d")
                    { [string] $ComputerADInfoShortOS += $ComputerADInfoShortOSArrayItem }
            }

        $ADDomainControllerReport = New-Object -TypeName PSObject 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name DCName -Value $ALLADForestDomainControllersItemName 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name Domain -Value $ALLADForestDomainControllersItemDomain 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name IP -Value $ALLADForestDomainControllersItemIPAddress 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name Site -Value $ALLADForestDomainControllersItemSiteName 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name Roles -Value $ALLADForestDomainControllersItemRoles 
        $ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name OS -Value $ComputerADInfoShortOS 
        #$ADDomainControllerReport | Add-Member -MemberType NoteProperty -Name Partition -Value $ALLADForestDomainControllersItemPartitions 
        
        [array]$AllADDomainControllerReport += $ADDomainControllerReport                      

    }
$AllADDomainControllerReport | Sort-Object DCName |  Format-Table -AutoSize -GroupBy Domain

# }
