[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

$global:SNAPI_SI = "service-now.com/api/now/v1/table/sn_si_incident"
$global:SNAPI_SI_Tag = "service-now.com/api/now/table/sn_sec_cmn_security_tag"
$global:SNAPI_SI_TagGrp = "service-now.com/api/now/table/sn_sec_cmn_security_tag_group"
$global:SNInstncAPI = "CHANGEME" #YOUR INSTANCE HERE

$global:TagGroup = ""
$global:TagGroups = ""
$global:Tag = ""
$global:Tags = ""

$global:MITRE = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
$global:MITREData = ""
$Global:MITRETactics = ""
$Global:MITRETechs = ""


#Get SN Creds and store it.
$global:SNCreds = Get-Credential

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
    $Global:MITRETactics = $MITREData.objects | ?{$_.type -eq 'x-mitre-tactic'} # ($MITREData.objects | ?{$_.kill_chain_phases.kill_chain_name -eq 'mitre-attack'}).kill_chain_phases.phase_name | Select -Unique | %{"$($TextInfo.ToTitleCase($_))"}
    $Global:MITRETechs = $MITREData.objects | ?{$_.type -eq 'attack-pattern'}
}


Function Tag-GroupCreate($TagGroupName,$Description){
    
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
            Write-Host "Tag Group " -NoNewline
            Write-Host $($TagGroupT.result.name) -ForegroundColor Green -NoNewline
            Write-host " was created"

            $global:TagGroup = $TagGroupT
        }
        Catch{
            Write-Host "Tag group couldn't be created - " -NoNewline
            Write-Host $TagGroupName -ForegroundColor Red
            Throw
        }
    }
}


Function Tag-GroupUpdate($GroupID,$TagGroupName,$Description){
    
        $TagName = ConvertTo-Json $TagGroupName
        $TagNote = ConvertTo-Json $Description
        $TagBodyFull = "{'name':$TagName,'description':$TagNote,'allow_multi':'true','active':'true'}"                  

        Try{
            $TagGroupT = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrp)/$GroupID" -Method Put -body $TagBodyFull -ContentType 'application/json' -Credential $global:SNcreds
            Write-Host "Tag Group " -NoNewline
            Write-Host $($TagGroupT.result.name) -ForegroundColor Green -NoNewline
            Write-host " was updated."

            $global:TagGroup = $TagGroupT
        }
        Catch{
            Write-Host "Tag group couldn't be updated - " -NoNewline
            Write-Host $TagGroupName -ForegroundColor Red
            Throw
        }

}

#SN colors dimgray,green,orange,deeppink,purple,black,blue,red
Function Tag-Create($TagName,$TagDesc,$TagGroupIn,$Order,$color){

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
            Write-Host "Tag " -NoNewline
            Write-Host $($Tag.result.name) -ForegroundColor Green -NoNewline
            Write-host " was created"

        
        }
        Catch{
            Write-Host "Tag couldn't be created - " -NoNewline
            Write-Host $TagName -ForegroundColor Red
            Throw
        }
  
}

Function Tag-Update($TagID,$TagName,$TagDesc,$TagGroupIn,$Order,$color){

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
            Write-Host "Tag " -NoNewline
            Write-Host $($Tag.result.name) -ForegroundColor Green -NoNewline
            Write-host " was updated"

        
        }
        Catch{
            Write-Host "Tag couldn't be updated - " -NoNewline
            Write-Host $TagName -ForegroundColor Red
            Throw
        }
}

Function Tag-GroupGet{

    Try{
        $TagGroupG = Invoke-RestMethod -uri "https://$($global:SNInstncAPI).$($global:SNAPI_SI_TagGrp)" -Method Get -ContentType 'application/json' -Credential $global:SNcreds
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
    Tag-GroupGet
    
    #Get Existing Tags
    Tag-Get
    
    #Create tag groups MITRE Tactics categories
    Foreach($Group in $Global:MITRETactics){
        #Check exist (specific tactic)
        If($TagGroups.result.name -cmatch "\[$($Group.external_references.external_id)\]"){
            Write-host "Updating Tactics ID [$($Group.external_references.external_id)] - $($Group.name)" -ForegroundColor Yellow
            $SysID = ($TagGroups.result | ?{$_.name -cmatch "\[$($Group.external_references.external_id)\]"})[0].sys_id            
            Tag-GroupUpdate -GroupID $SysID -TagGroupName "MITRE [$($Group.external_references.external_id)] - $($Group.name)" -Description "$($Group.description)`n`n$($Group.external_references.url)"
            #$SysID
        }
    
        #Create if not
        Else{
            Tag-GroupCreate -TagGroupName "MITRE [$($Group.external_references.external_id)] - $($Group.name)" -Description "$($Group.description)`n`n$($Group.external_references.url)"
            Tag-GroupGet
            $SysID = ($TagGroups.result | ?{$_.name -cmatch "\[$($Group.external_references.external_id)\]"})[0].sys_id
            #$SysID
        }

        Foreach($Tech in ($MITRETechs | ?{$_.kill_chain_phases.phase_name -eq $Group.x_mitre_shortname})){
            
            
            If($Tags.result | ?{$_.security_tag_group.value -eq $SysID -and $_.name -match "\[$(@($Tech.external_references.external_id)[0])\]"}){
                Write-host "Updating Technique ID [$(@($Tech.external_references.external_id)[0])] - $($Tech.name)" -ForegroundColor Yellow
                $TSysID = ""
                $TSysID = ($Tags.result | ?{$_.security_tag_group.value -eq $SysID -and $_.name -match "\[$(@($Tech.external_references.external_id)[0])\]"})[0].sys_id
                #$TSysID
                
                $TagIn = ""
                $TagIn = "[$(@($Tech.external_references.external_id)[0])] - $($Tech.name)"
                $DescIn = ""
                $DescIn = $Tech.description -replace "[^\x00-\x7F]", ""
                $ordr = [int]([decimal]((@($Tech.external_references.external_id)[0])[1..10] -join "")*1000)

                Tag-Update -TagID $TSysID -TagName $TagIn -TagDesc $DescIn -TagGroupIn $SysID -Order $ordr -color 'blue'
            }
    
            #Create if not
            Else{
                Write-Host "Building Technique ID [$(@($Tech.external_references.external_id)[0])] - $($Tech.name)"               
                $TagIn = ""
                $TagIn = "[$(@($Tech.external_references.external_id)[0])] - $($Tech.name)"
                $DescIn = ""
                $DescIn = $Tech.description -replace "[^\x00-\x7F]", ""
                $ordr = [int]([decimal]((@($Tech.external_references.external_id)[0])[1..10] -join "")*1000)

                Tag-Create -TagName $TagIn -TagDesc $DescIn -TagGroupIn $SysID -Order $ordr -color 'blue'
            }        
            
        
        }

    }

}
Catch{
    Write-Host "Something bad happened, good luck figuring it out." -ForegroundColor Red
}
