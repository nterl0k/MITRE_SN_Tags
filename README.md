# MITRE Service-Now Security Tags
Import MITRE Tactics and Techniques as Service-Now Security Tag Groups and Tags [Updated for Oct 2020 MITRE changes]

- Pulls down the latest framework from https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json.
- Uses the Service-Now API to import MITRE Tactics as "Tag Groups"
  - Names these groups based on TA#### i.e. [TA0002] - Execution
- Associates each Technique per Tactic as a Tag under these "Tag Groups".
  - Techniques named similarly i.e [T1078] - Valid Accounts
- Rerunning the script will update any existing Tactic/Techniques built by the script with the latest info from MITRE json.


## Requirements
- This requires Security Incident Operations/Security Incident Response installed in your Service-Now instance.

## Installation/Config
  Script needs minor changes for your Service-Now instance
  - Change line 6 '$global:SNInstncAPI = "CHANGME" #YOUR INSTANCE HERE' to your instance short name: The [MYINSTANCE] in [MYINSTANCE].service-now.com
  - Script asks for credentials with access to your instance, this should an account allowed to add/remove tags.
  
  
### Script Running - Output shows success/failure/updates
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/Script%20Running.png?raw=true)

### MITRE Tactics(Tag Groups)
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag%20Groups.png?raw=true)

### MITRE Techniques(Tags) in a Tactic(Tag Group)
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag%20Group.png?raw=true)

### MITRE Technique(Tag) Detail
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/MITRE%20Tag.png?raw=true)

### MITRE Tactic/Technique selection in a security incident
![alt text](https://github.com/nterl0k/MITRE_SN_Tags/blob/master/images/Incident%20Tagging.png?raw=true)
