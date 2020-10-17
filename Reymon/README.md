# Reymon

Reymon is a tool developed with the task of aiding Security Analysts with automating part of their workflow. The primary goals of Reymon is to perform reputation checks of multiple DNS/IP/File Hash at a time with CSV file as input, allowing the analyst more time to spend on deeper analysis within the same time-frame. 


## Functionality

 - Perform reputation checks for multiple DNS/IP/File Hash.
 - It's integrated with API's from:
     -   [VirusTotal](https://www.virustotal.com/)
     -   [AlienVault](https://otx.alienvault.com/)
     -   [Abuse IPDB](https://www.abuseipdb.com/)
  

## Points to note

 1. While selecting the input method, just input the number.
 2. The Input file incase of multiple IP/URL/Domain/File Hash, the file type should be .csv (Comma separated value), NOT the one with UTF-8 signature.
 3. The input data should always be copied in column A of the sheet one after the other, there is no restriction on maximum IP, url,
    etc.
 4. The input file must be saved in same directory as the reymon
    application.
 5. While inputting the filename use format “filename.csv”. Input in CLI
    is case sensitive.
