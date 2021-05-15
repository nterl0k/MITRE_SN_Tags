# MITRE Service-Now Security Tags
Import MITRE Tactics and Techniques as Service-Now Security Tag Groups and Tags [Updated for v9 MITRE changes]

- Pulls down the latest framework from https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json.
- Uses the Service-Now API to import MITRE Tactics as "Security Tag Groups"
  - Names these groups based on the TA#### name schema. i.e. "[TA0002] - Execution".</p>
- Associates each Technique per Tactic as a "Security Tag" under the "Tag Groups".
  - Techniques named similarly via the T#### name schema. i.e "[T1078] - Valid Accounts".</p>
- Rerunning the script will update any existing Tactic/Techniques built by the script with the latest info from MITRE json.
  -  Script will now only attempt an update to SNow instance object when a tactic/technique is changed (Faster)
  -  Script will also disabled any tags (techniques) listed as revoked in the MITRE JSON.</p>

## Requirements
- This requires Security Incident Operations/Security Incident Response installed in your Service-Now instance.

## Installation/Config
  Script needs minor changes for your Service-Now instance
  - Change line 6 '$global:SNInstncAPI = "CHANGME" #YOUR INSTANCE HERE' to your instance short name: The [MYINSTANCE] in [MYINSTANCE].service-now.com
  - Script asks for credentials with access to your instance, this should be an account allowed to add/remove tags.
  - Script verbosity is muted by default.
     -   This can be disabled by setting the variable '$global:mute' on line 39 to $false</p>
  - Script now produces a simple HTML report upon completion that can be used as a change/validation artifact.
     -   This can be disabled by setting the variable '$global:report' on line 40 to $false</p>  
  
### Script Running - Output shows. Change the  success/failure/updates at end. 
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/Script%20Running.png?raw=true)

### MITRE Tactics(Tag Groups)
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag%20Groups.png?raw=true)

### MITRE Techniques(Tags) in a Tactic(Tag Group)
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag%20Group.png?raw=true)

### MITRE Technique(Tag) Detail
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag.png?raw=true)

### MITRE Tactic/Technique selection in a security incident
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/Incident%20Tagging.png?raw=true)

### Output HTML Report
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/HTML%20Report.png?raw=true)
