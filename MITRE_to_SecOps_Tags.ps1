
<#
.SYNOPSIS
    Script that walks the MITRE ATT&CK framework and adds tags to Service-Now.

.DESCRIPTION
    A script that will download the JSON version of ATT&CK from the MITRE Github, then parse
    the contents of the download for tactics and techniques. The data is then injected into 
    Service-Now as Security Tag Groups and Security Tags.

.EXAMPLE
    C:\PS>./MITRE_SN_Tags.ps1 
            This runs the command in default mode, will prompt for SNow credentials 
.NOTES
    Author: Nterl0k
    Date:   May 6, 2021
    Version: 1.2    
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$global:SNAPI_SI = "service-now.com/api/now/v1/table/sn_si_incident"
$global:SNAPI_SI_Tag = "service-now.com/api/now/table/sn_sec_cmn_security_tag"
$global:SNAPI_SI_TagLink = "service-now.com/nav_to.do?uri=%2Fsn_sec_cmn_security_tag.do%3Fsys_id%3D"
$global:SNAPI_SI_TagGrp = "service-now.com/api/now/table/sn_sec_cmn_security_tag_group"
$global:SNInstncAPI = "CHANGEME" #YOUR INSTANCE HERE
$global:SNAPI_SI_TagGrpLink = "service-now.com/nav_to.do?uri=%2Fsn_sec_cmn_security_tag_group.do%3Fsys_id%3D" 

$global:TagGroup = ""
$global:TagGroups = ""
$global:Tag = ""
$global:Tags = ""

$global:MITRE = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
$global:MITREData = ""
$Global:MITRETactics = ""
$Global:MITRETechs = ""
$Global:ReportOut = @()
$Global:Mute = $true
$Global:report = $true

#<#Get SN Creds and store it.

$global:SNCreds = Get-Credential
#>

Function Get-MITRE{
#Get MITREData
    Write-Host "Attempting to get latest MITRE ATT&CK info..."
    Try{
        $global:MITREData = Invoke-RestMethod -Uri $global:MITRE
        Write-Host "Download success: $global:MITRE" -ForegroundColor Green
        }
    Catch{
        Write-Host "Download failed: $global:MITRE" -ForegroundColor Red
        Throw
    }

    #Get MITRE Stages-Tactics
    $Global:MITRETactics = $MITREData.objects | ?{$_.type -eq 'x-mitre-tactic'} | Sort {$_.external_references.external_id} # ($MITREData.objects | ?{$_.kill_chain_phases.kill_chain_name -eq 'mitre-attack'}).kill_chain_phases.phase_name | Select -Unique | %{"$($TextInfo.ToTitleCase($_))"}
    $Global:MITRETechs = $MITREData.objects | ?{($_.type -eq 'attack-pattern') -and ($_.revoked -ne $true)}
    $Global:MITRESubTechs = $MITREData.objects | ?{($_.type -eq 'attack-pattern') -and ($_.revoked -ne $true) -and ($_.x_mitre_is_subtechnique -eq $true)}
    $Global:MITREREvokes = $MITREData.objects | ?{($_.type -eq 'attack-pattern') -and ($_.revoked -eq $true)}

    Write-Host "`nMITRE ATT&CK Framework currently contains:`n" -NoNewline
    Write-Host "`t$($Global:MITRETactics.count)" -NoNewline -ForegroundColor Green
    Write-Host " total tactics`n" -NoNewline
    Write-Host "`t$($Global:MITRETechs.count - $Global:MITRESubTechs.count)" -NoNewline -ForegroundColor Green
    Write-Host " total techniques`n" -NoNewline
    Write-Host "`t$($Global:MITRESubTechs.count)" -NoNewline -ForegroundColor Green
    Write-Host " total subtechniques`n`n" -NoNewline
    Write-Host "`t$($Global:MITREREvokes.count)" -NoNewline -ForegroundColor Yellow
    Write-Host " total revoked items`n`n" -NoNewline
    Write-Host "Latest Update:`n" -NoNewline
    Write-Host "`t$(Get-Date(($Global:MITREData.objects.modified | sort)[-1]) -Format G)`n" -ForegroundColor Green

}

Function Tag-GroupCreate($TagGroupName,$Description){
    $ReportOutT = "" | Select Name,Type,Parent,Action,Result,Link
    $ReportOutT.Name = $TagGroupName
    $ReportOutT.Type = "Tactic"
    $ReportOutT.Action = "Create"
    $ReportOutT.Parent = $TagGroupName

    If($TagGroupName -iin $TagGroups.result.name){    
        Write-Host "Tag Group Named `"$TagGroupName`" already exists, skipping." -ForegroundColor Red
    }
    Else{
        Write-Host "Tag Group Named `"$TagGroupName`" doesn't exist, attempting to create." -ForegroundColor Green
        $TagName = ConvertTo-Json $TagGroupName
        $TagNote = ConvertTo-Json $Description
        $TagBodyFull = "{'name':$TagName,'description':$TagNote,'allow_multi':'true','active':'true'}"                  

        Try{
            $TagGroupT = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrp)" -Method Post -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds
            If($Global:Mute ){}Else{
            Write-Host "Tag Group " -NoNewline
            Write-Host $($TagGroupT.result.name) -ForegroundColor Green -NoNewline
            Write-host " was created"}
            $global:TagGroup = $TagGroupT
            $ReportOutT.Result = "Success"
            $ReportOutT.Link = "<a href = `"https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrpLink)$($TagGroupT.Result.Sys_id)`" target = `"_self`">$($TagGroupT.result.name)</a>"
            $Global:ReportOut += $ReportOutT
        }
        Catch{
            If($Global:Mute ){}Else{
            Write-Host "Tag group couldn't be created - " -NoNewline
            Write-Host $TagGroupName -ForegroundColor Red}
            $ReportOutT.Result = "Fail"
            $Global:ReportOut += $ReportOutT
            Throw
        }
    }
}

Function Tag-GroupUpdate($GroupID,$TagGroupName,$Description){
    $ReportOutT = "" | Select Name,Type,Parent,Action,Result,Link
    $ReportOutT.Name = $TagGroupName
    $ReportOutT.Type = "Tactic"
    $ReportOutT.Action = "Update"
    $ReportOutT.Parent = $TagGroupName
        
        $TagName = ConvertTo-Json $TagGroupName
        $TagNote = ConvertTo-Json $Description
        $TagBodyFull = "{'name':$TagName,'description':$TagNote,'allow_multi':'true','active':'true'}"                  

        Try{
            $TagGroupT = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrp)/$GroupID" -Method Put -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds
            If($Global:Mute ){}Else{
            Write-Host "Tag Group " -NoNewline
            Write-Host $($TagGroupT.result.name) -ForegroundColor Green -NoNewline
            Write-host " was updated."}
            $global:TagGroup = $TagGroupT
            $ReportOutT.Result = "Success"
            $ReportOutT.Link = "<a href = `"https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrpLink)$($TagGroupT.Result.Sys_id)`" target = `"_self`">$($TagGroupT.result.name)</a>"
            $Global:ReportOut += $ReportOutT
        }
        Catch{
            If($Global:Mute ){}Else{
            Write-Host "Tag group couldn't be updated - " -NoNewline
            Write-Host $TagGroupName -ForegroundColor Red}
            $ReportOutT.Result = "Fail"
            $Global:ReportOut += $ReportOutT
            Throw
        }

}


#SN colors dimgray,green,orange,deeppink,purple,black,blue,red
Function Tag-Create($TagName,$TagDesc,$TagGroupIn,$TagGroupName,$Order,$color){
        $ReportOutT = "" | Select Name,Type,Parent,Action,Result,Link
        $ReportOutT.Name = $TagName
        $ReportOutT.Type = "Technique"
        $ReportOutT.Action = "Create"
        $ReportOutT.Parent = $TagGroupName

        $TagBody = "" | Select name,description,active,order,color,security_tag_group   
        $Tagbody.name = $TagName
        $Tagbody.description = $TagDesc
        $Tagbody.active = 'true'
        $Tagbody.order = $order
        $Tagbody.color = $color
        $Tagbody.security_tag_group = $TagGroupIn

        $TagBodyFull = ConvertTo-Json $TagBody

        Try{
            $Tag = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_Tag)" -Method Post -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds
            If($Global:Mute ){}Else{
            Write-Host "Tag " -NoNewline
            Write-Host $($Tag.result.name) -ForegroundColor Green -NoNewline
            Write-host " was created"}
            $ReportOutT.Result = "Success"
            $ReportOutT.Link = "<a href =`"https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagLink)$($Tag.Result.Sys_id)`" target =`"_self`">$($Tag.result.name)</a>"
            $Global:ReportOut += $ReportOutT
        
        }
        Catch{
            If($Global:Mute ){}Else{
            Write-Host "Tag couldn't be created - " -NoNewline
            Write-Host $TagName -ForegroundColor Red}
            $ReportOutT.Result = "Fail"
            $Global:ReportOut += $ReportOutT            
            Throw
        }
  
}

Function Tag-Update($TagID,$TagName,$TagDesc,$TagGroupIn,$TagGroupName,$Order,$color){
        $ReportOutT = "" | Select Name,Type,Parent,Action,Result,Link
        $ReportOutT.Name = $TagName
        $ReportOutT.Type = "Technique"
        $ReportOutT.Action = "Update"
        $ReportOutT.Parent = $TagGroupName

        $TagBody = "" | Select name,description,active,order,color,security_tag_group   
        $Tagbody.name = $TagName
        $Tagbody.description = $TagDesc
        $Tagbody.active = 'true'
        $Tagbody.order = $order
        $Tagbody.color = $color
        $Tagbody.security_tag_group = $TagGroupIn

        $TagBodyFull = ConvertTo-Json $TagBody

        Try{
            $Tag = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_Tag)/$TagID" -Method Put -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds            
            If($Global:Mute ){}Else{
            Write-Host "Tag " -NoNewline
            Write-Host $($Tag.result.name) -ForegroundColor Green -NoNewline
            Write-host " was updated"}
            $ReportOutT.Result = "Success"
            $ReportOutT.Link = "<a href =`"https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagLink)$($Tag.Result.Sys_id)`" target =`"_self`">$($Tag.result.name)</a>"
            $Global:ReportOut += $ReportOutT
        
        }
        Catch{
            If($Global:Mute ){}Else{
            Write-Host "Tag couldn't be updated - " -NoNewline
            Write-Host $TagName -ForegroundColor Red}
            $ReportOutT.Result = "Fail"
            $Global:ReportOut += $ReportOutT            
            Throw
        }
}

Function Tag-Revoke($TagID,$TagName,$TagGroup){
        $ReportOutT = "" | Select Name,Type,Parent,Action,Result,Link
        $ReportOutT.Name = $TagName
        $ReportOutT.Type = "Technique"
        $ReportOutT.Action = "Revoke"
        $ReportOutT.Parent = $TagGroup

        $TagBody = "" | Select name,active
        $Tagbody.name = $TagName
        $Tagbody.active = 'false'

        $TagBodyFull = ConvertTo-Json $TagBody

        Try{
            $Tag = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_Tag)/$TagID" -Method Put -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds            
            If($Global:Mute ){}Else{
            Write-Host "Tag " -NoNewline
            Write-Host $($Tag.result.name) -ForegroundColor Green -NoNewline
            Write-host " was revoked"}
            $ReportOutT.Result = "Success"
            $ReportOutT.Link = "<a href =`"https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagLink)$($Tag.Result.Sys_id)`" target =`"_self`">$($Tag.result.name)</a>"
            $Global:ReportOut += $ReportOutT
        
        }
        Catch{
            If($Global:Mute ){}Else{
            Write-Host "Tag couldn't be revoked - " -NoNewline
            Write-Host $TagName -ForegroundColor Red}
            $ReportOutT.Result = "Fail"
            $Global:ReportOut += $ReportOutT            
            Throw
        }
}

Function Tag-GroupGet{

    Try{
        $TagGroupG = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrp)" -Method Get -ContentType 'application/json' -Credential $global:SNcreds
        If($TagGroupG -match "instance is hibernating"){
            Write-Host "Instance is hibernating" -ForegroundColor Red
            throw
        }
        Write-Host "Found " -NoNewline
        Write-Host $($TagGroupG.result.count) -ForegroundColor Green -NoNewline
        Write-host " Tag Groups."

        $global:TagGroups = $TagGroupG
    }
    Catch{
        Write-Host "Tag groups couldn't be fetched" -ForegroundColor Red
        Throw
    }
}

Function Tag-Get{

    Try{
        $TagsG = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_Tag)" -Method Get -ContentType 'application/json' -Credential $global:SNcreds
        If($TagsG -match "instance is hibernating"){
            Write-Host "Instance is hibernating" -ForegroundColor Red
            throw
        }
        Write-Host "Found " -NoNewline
        Write-Host $($TagsG.result.count) -ForegroundColor Green -NoNewline
        Write-host " Tags."

        $global:Tags = $TagsG
    }
    Catch{
        Write-Host "Tags couldn't be fetched" -ForegroundColor Red
        Throw
    }
}

#Write-Host "Attempting to create MITRE tag group"
Try{
    #Get Updated MITRE Framework
    Get-MITRE
   
    #Get Existing Tag Groups
    Write-Host "Querying for exisitng Security Tag Groups and Tags on " -NoNewline
    Write-host "$global:SNInstncAPI.servicenow.com" -ForegroundColor Green
    Tag-GroupGet
    

    #Get Existing Tags
    Tag-Get
    
    #Gather and revoke any existing tags.
    #Write-Host "Examining tags that need to be revoked..." -NoNewline
      
    $Revoked = (($MITREData.objects | ?{($_.type -eq 'attack-pattern') -and ($_.revoked -eq $true)}).external_references)
    $Revoked = ($Revoked | ?{$_.source_name -eq "mitre-attack"}).external_id | Select -unique | sort
    $Revoked = $Revoked | ?{$_ -Match "T.+"}

    Foreach($Revoke in $Revoked){
        Write-progress -Activity "MITRE to SecOps Tagging" -Id 1 -Status "Attemping to revoke [$Revoke]" -PercentComplete ($Revoked.IndexOf($Revoke)/@($Revoked).count*100)
        $Revokedtag = $Tags.result | ?{$_.name -match "^\[$Revoke].+"}
        
        
        If(@($Revokedtag.count) -gt 0){
            Foreach($RevokeTag in $Revokedtag){
                $RevokeGroup = ($TagGroups.result | ?{$_.sys_id -eq $RevokeTag.security_tag_group.value}).name
                Tag-Revoke -TagID $RevokeTag.sys_id $RevokeTag.name $RevokeGroup
                      
            }
        }
     }
        
    Write-Progress -Activity "MITRE to SecOps Tagging" -Completed

    #Create tag groups MITRE Tactics categories
    Foreach($Group in $Global:MITRETactics){
        
        $DescIn = $Group.description -replace "[^\x00-\x7F]", ""
        $GroupName = "MITRE [$($Group.external_references.external_id)] - $($Group.name)"

        Write-progress -Activity "MITRE to SecOps Tagging" -Id 1 -Status "Working on [$GroupName]" -PercentComplete ($Global:MITRETactics.IndexOf($Group)/@($Global:MITRETactics).count*100)       

        #Check exist (specific tactic)
        If($TagGroups.result.name -cmatch "\[$($Group.external_references.external_id)\]"){
            IF($TagGroups.result.description -eq "$($DescIn)`n`n$($Group.external_references.url)"){
                $SysID = ($TagGroups.result | ?{$_.name -cmatch "\[$($Group.external_references.external_id)\]"})[0].sys_id
            }
            Else{
                If($Global:Mute ){}Else{Write-host "Updating Tactics ID [$($Group.external_references.external_id)] - $($Group.name)" -ForegroundColor Yellow}           
                $SysID = ($TagGroups.result | ?{$_.name -cmatch "\[$($Group.external_references.external_id)\]"})[0].sys_id            
                Tag-GroupUpdate -GroupID $SysID -TagGroupName $GroupName -Description "$($DescIn)`n`n$($Group.external_references.url)"            
                #$SysID
            }
        }
    
        #Create if not
        Else{
            Tag-GroupCreate -TagGroupName $GroupName -Description "$($Group.description)`n`n$($Group.external_references.url)"
            Tag-GroupGet
            $SysID = ($TagGroups.result | ?{$_.name -cmatch "\[$($Group.external_references.external_id)\]"})[0].sys_id
            #$SysID
        }
        
        $MITRETechsT = $MITRETechs | ?{$_.kill_chain_phases.phase_name -eq $Group.x_mitre_shortname} | sort {($_.external_references | ? {$_.source_name -eq "mitre-attack"}).external_id} 

        Foreach($Tech in $MITRETechsT){            
                            
            $TagIn = ""
            $DescIn = ""
            $TechID = ($Tech.external_references | ? {$_.source_name -eq "mitre-attack"}).external_id
            $TechShort = [decimal](($TechID)[1..10] -join "")

            #$TechShort = [decimal]((@($Tech.external_references.external_id)[0])[1..10] -join "") #old
            $TechName = $Tech.name -replace "[^\x00-\x7F]", ""
            $TagIn = "[$TechID] - $TechName"
            $DescIn = $Tech.description -replace "[^\x00-\x7F]", ""
            $ordr = [int]($TechShort*1000)
            
            Write-progress -ParentId 1 -Activity "Creating/Updating Techniques" -Status "Working on $TagIn" -PercentComplete ($Global:MITRETechsT.IndexOf($Tech)/@($Global:MITRETechsT).count*100)

            If($Tags.result | ?{$_.security_tag_group.value -eq $SysID -and $_.name -match "\[$TechID\]"}){
                If($Tags.result | ?{$_.security_tag_group.value -eq $SysID -and $_.description -eq $DescIn}){
                }
                Else{
                    If($Global:Mute ){}Else{Write-host "Updating Technique ID [$TechID] - $TechName" -ForegroundColor Yellow}
                    $TSysID = ""
                    $TSysID = ($Tags.result | ?{$_.security_tag_group.value -eq $SysID -and $_.name -match "\[$TechID\]"})[0].sys_id
                    #$TSysID
                
                    Tag-Update -TagID $TSysID -TagName $TagIn -TagDesc $DescIn -TagGroupIn $SysID -TagGroupName $GroupName -Order $ordr -color 'blue'
                }
            }
    
            #Create if not
            Else{
                If($Global:Mute ){}Else{Write-Host "Building Technique ID [$TechID] - $TechName"}               
               
                Tag-Create -TagName $TagIn -TagDesc $DescIn -TagGroupIn $SysID -TagGroupName $GroupName -Order $ordr -color 'blue'
            }        
            
        
        }
        
        
    }
    
    Write-Progress -Activity "MITRE to SecOps Tagging" -Completed

    Write-Host "MITRE to SecOps Tagging Completed."
    Write-Host "`t Tactics created: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Tactic" -and $_.Action -eq "Create" }).Count)" -ForegroundColor Green
    Write-Host "`t Tactics updated: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Tactic" -and $_.Action -eq "Update" }).Count)" -ForegroundColor Yellow
    Write-Host "`t Tactics failed: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Tactic" -and $_.Result -eq "Fail" }).Count)" -ForegroundColor Red
    Write-Host ""
    Write-Host "`t Technique created: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Technique" -and $_.Action -eq "Create" }).Count)" -ForegroundColor Green
    Write-Host "`t Technique updated: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Technique" -and $_.Action -eq "Update" }).Count)" -ForegroundColor Yellow
    Write-Host "`t Technique revoked: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Technique" -and $_.Action -eq "Revoke" }).Count)" -ForegroundColor Yellow
    Write-Host "`t Technique failed: " -NoNewline
    Write-Host "$(@($ReportOut | ?{$_.Type -eq "Technique" -and $_.Result -eq "Fail" }).Count)" -ForegroundColor Red
    Write-Host ""    
    }
Catch{
    Write-Host "Something bad happened, good luck figuring it out." -ForegroundColor Red      
}

If($Global:report -eq $true){
#region Title of browser tab
$ReportName = "SecOps Tagging Report"
$Title = "SecOps Tagging Report"
$HtmlTitle = "<title> $Title </title> `n"

#endregion

#region Header and styling variable
$HtmlStyle  = "<head>
<style>
	table {
	border-collapse: collapse;
	table-layout: auto;
	min-width:100%;
	max-width:150%;
	}
	th, td {
	border: 1px solid #ccc;
	padding: 10px;
	vertical-align: top;
	text-align: left;
	max-width: 700px;
	word-wrap: break-word;
	}
	tr:nth-child(even) {
	background-color: #eee;
	}
	tr:nth-child(odd) {
	background-color: #fff;
	} 
	button.accordion {
	background-color: #eee;
	color: #444;
	cursor: pointer;
	padding: 18px;
	width: 100%;
	border: none;
	text-align: left;
	outline: none;
	font-size: 15px;
	transition: 0.4s;
}
button.accordion.active, button.accordion:hover {
	background-color: #ccc;
}
button.accordion:after {
	content: `"\002B`";
	color: #777;
	font-weight: bold;
	float: right;
	margin-left: 5px;
}
button.accordion.active:after {
	content: `"\2212`";
}
div.panel {
	padding: 0 18px;
	background-color: white;
	max-height: 0;
	overflow: auto;
	transition: max-height 0.2s ease-out;
}
/* Style the tab */
div.tab {
	overflow: hidden;
	border: 1px solid #ccc;
background-color: #f1f1f1;
}
/* Style the buttons inside the tab */
div.tab button {
	background-color: inherit;
	float: left;
	border: none;
	outline: none;
	cursor: pointer;
	padding: 14px 16px;
	font-size: 18px;
	font-weight: Bold;
	transition: 0.5s;
}
/* Change background color of buttons on hover */
div.tab button:hover {
	background-color: #ddd;
}
/* Create an active/current tablink class */
div.tab button.active {
	background-color: #ccc;
}
/* Style the tab content */
.tabcontent {
	display: none;
	padding: 12px 12px;
	border: 1px solid #ccc;
	border-top: none;
}
</style>
</head>"

#endregion

#region PNG logo encoded as Base64
$HtmlLogo = "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"


#endregion

#region Banner title for report page
$HtmlSubTitle = "<p>
<table width = 100%; border=`"0`">
<tr width=`"100%;`">
      <td width=`"65%;`" align=`"center`" valign=`"center`"><BR><font size=`"6`"><strong>S</strong>ervice-<strong>N</strong>ow <strong>MITRE</strong> <strong>T</strong>agging <strong>R</strong>eport</font> </td>
      <td width=`"35%;`" valign=`"bottom`"> <img alt=`"`" src=`"data:image/png;base64,$HtmlLogo`"style=`"float: right; width: auto; height: auto;max-width: 120px;max-height: 100px`"> </td>
<tr>
<td colspan=`"2`" width=`"100%;`" align=`"center`" valign=`"center`"> <font size=`"4`"><strong>	Target &nbsp;&nbsp;&nbsp;&nbsp;-&nbsp;&nbsp;&nbsp;&nbsp;https://$SNInstncAPI.service-now.com <br>User&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-&nbsp;&nbsp;&nbsp;&nbsp;$($env:USERNAME.ToUpper()) 
</strong></font> </td>
</tr>
</tr>
</table>
</p>"

#endregion

#region Assemble Tabs
#Loops through input array and builts dynamic subtabs based on 2nd and 3rd columns of input array;

$ReportTabs = ("Summary","Detailed")
$HtmlTabs = "<div class=`"tab`">`n"
$HtmlSection = ""

Foreach($Tab in $ReportTabs){
	$HtmlTabs += "<button class=`"tablinks`" onclick=`"openCity(event, `'$Tab`')`">$Tab</button> `n"
	$HtmlSection += "<div id=`"$Tab`" class=`"tabcontent`"> `n"
                 If($Tab -eq "Summary"){
                       
                    
                    $DetectsIn = $ReportOut | Group Type,Action -NoElement | Select Name,Count 
                    
                    $DetectsRep = @()
                    
                    Foreach($Detect in $DetectsIn){
                    $Detect.Name = $Detect.Name -replace "create", "<font color=green>Create</font>"
                    $Detect.Name = $Detect.Name -replace "revoke", "<font color=orange>Revoke</font>"
                    $Detect.Name = $Detect.Name -replace "update", "<font color=blue>Update</font>"

                    $Detect.Name = $Detect.Name -replace "Success", "<font color=green><strong>Success</strong></font>"
                    $Detect.Name = $Detect.Name -replace "Fail", "<font color=red><strong>Fail</strong></font>"

                    
                    $DetectsRep += $Detect
                    }

                    $Detects = $DetectsRep | Convertto-HTML -Fragment
                    $Detects2 = [System.Web.HTTPUtility]::HtmlDecode($Detects) | Out-String
                    $sResult = 	"<table style='font-family`"Courier New`", Courier, monospace; font-size:80%' border=`"1`">
                    $Detects2 
                    </table>"
                    $HtmlSection += $sResult                 
                 }
                 ElseIf($tab -eq "Detailed"){
                    Foreach($Tactic in $($ReportOut.Parent | Select -Unique)){
                    
                        $DetectsIn = $ReportOut | ?{$_.Parent -eq $Tactic}                   
                        $DetectC = "<font color=green>$($($DetectsIn.Action | ?{$_ -match "create"}).count)</font>"
                        $DetectR = "<font color=orange>$($($DetectsIn.Action | ?{$_ -match "revoke"}).count)</font>"
                        $DetectU = "<font color=blue>$($($DetectsIn.Action | ?{$_ -match "update"}).count)</font>"
                        $DetectsRep = @()
                      
                        Foreach($Detect in $DetectsIn){
                            $Detect.Action = $Detect.Action -replace "create", "<font color=green>$($Detect.Action)</font>"
                            $Detect.Action = $Detect.Action -replace "revoke", "<font color=orange>$($Detect.Action)</font>"
                            $Detect.Action = $Detect.Action -replace "update", "<font color=blue>$($Detect.Action)</font>"

                            $Detect.Result = $Detect.Result -replace "Success", "<font color=green><strong>$($Detect.Result)</strong></font>"
                            $Detect.Result = $Detect.Result -replace "Fail", "<font color=red><strong>$($Detect.Result)</strong></font>"
                    
                            $DetectsRep += $Detect
                        }
                    
                            $Detects = $DetectsRep | Select Name,Type,Action,Result,Link | Convertto-HTML -Fragment
                            $Detects2 = [System.Web.HTTPUtility]::HtmlDecode($Detects) | Out-String



                        $sResult = 	"<button class=`"accordion`" style=`"padding-left: 50px`">$($Tactic)</br>Created:<strong>$DetectC</strong></br>Updated:<strong>$DetectU</strong></br>Revoked:<strong>$DetectR</strong></button>
					    <div class=`"panel`">
					    <table style='font-family`"Courier New`", Courier, monospace; font-size:100%' border=`"1`">
                        <tr><td> $Detects2 </td></tr>
                        </table>
                        </div>"
                        $HtmlSection += $sResult

                    }                    
                  
                    }
		$HtmlSection += "</div>`n"
}

$HtmlTabs += "</div>`n"
#endregion

#region Scripting section variable
$HtmlScript = "<script>
var acc = document.getElementsByClassName(`"accordion`");
var i;
for (i = 0; i < acc.length; i++) {
	acc[i].onclick = function() {
	this.classList.toggle(`"active`");
	var panel = this.nextElementSibling;
	if (panel.style.maxHeight){
		panel.style.maxHeight = null;
	} else {
		panel.style.maxHeight = panel.scrollHeight + `"px`";
	} 
	}
}
function openCity(evt, cityName) {
	// Declare all variables
	var i, tabcontent, tablinks;

	// Get all elements with class=`"tabcontent`" and hide them
	tabcontent = document.getElementsByClassName(`"tabcontent`");
	for (i = 0; i < tabcontent.length; i++) {
		tabcontent[i].style.display = `"none`";
	}

	// Get all elements with class=`"tablinks`" and remove the class `"active`"
		tablinks = document.getElementsByClassName(`"tablinks`");
	for (i = 0; i < tablinks.length; i++) {
		tablinks[i].className = tablinks[i].className.replace(`" active`", `"`");
	}

	// Show the current tab, and add an `"active`" class to the button that opened the tab
		document.getElementById(cityName).style.display = `"block`";
	evt.currentTarget.className += `" active`";
}
</script>"
#endregion

#region Build Report Object
$html = "<html>`n
$HtmlTitle `n
$HtmlStyle `n
<body>`n
$HtmlSubTitle `n
$HtmlTabs `n
$HtmlSection `n
</body> `n
$HtmlScript `n
</html>`n"
#endregion

$DesktopPath = [Environment]::GetFolderPath("Desktop")
$save = "$DesktopPath\SN_SecOps_Tagging_$(get-date -f MMddyyyy-HHss).html"
$html | Out-File $save -Force

Write-Host "Report saved to $save"
Write-Host ""

Start $save

}

pause
