# MITRE Service-Now Security Tags
Import MITRE Tactics and Techniques as Service-Now Security Tag Groups and Tags

- Pulls down the latest framework from https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json.
- Uses the Service-Now API to import MITRE Tactics as "Tag Groups"
  - Names these groups based on TA#### i.e. [TA0002] - Execution
- Associates each Technique per Tactic as a Tag under these "Tag Groups".
  - Techniques named similarly i.e [T1078] - Valid Accounts
  
  Script needs minor changes for your Service-Now instance
  - Change line 6 '$global:SNInstncAPI = "CHANGME" #YOUR INSTANCE HERE' to your instance short name: The MYINSTANCE in MYINSTANCE.service-now.com
  - Script will need to access your instance using an account allowed to add/remove tags.
