#!/usr/bin/python

import csv
import base64
import requests
import json
import sys
import re

def main():
     
    print("\n --------------------------------- ")
    print("            R E Y M O N            ")
    print(" --------------------------------- ")

       
    VT_API = "<virus total API>"
    AbuseIP_API = "<Abuse IPDB API>"
    AV_API = "<Alien Vault API>"
    
    def IPChecker_CSV():
        print("\n ----------------------------------- ")
        print("      I P   R E P U T A T I O N      ")
        print(" ----------------------------------- ")

        #opening file as CSV and iteration row by row on column A
        inputFilename = input("Enter file name containing IP Address: ")

        if re.search(".csv", inputFilename):
                        
            with open(inputFilename) as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:

                    print("\nDetails for IP:", row[0])
                    try:    
                        #calling Abuse IPDb to check reputation
                        url = 'https://api.abuseipdb.com/api/v2/check'
                        querystring = {
                            'ipAddress': row[0],
                            'maxAgeInDays': '90'
                        }
                        headers = {
                            'Accept': 'application/json',
                            'Key': AbuseIP_API
                        }
                        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
                        decodedResponse = json.loads(response.text)

                        if response.status_code == 200:
                            #simplifying the JSON output for priniting the result
                            x = decodedResponse['data']
                        
                            print('Domain Name:', x['domain'])
                            print('ISP:', x['isp'])
                            print('Country Code:', x['countryCode'])
                            print('ABUSE IPDB - Abuse confidence score:', x['abuseConfidenceScore'])

                        else:
                            print('Error loading Abuse IPDB result')          
                    
                    except:
                        print('ABUSE IPDB - IP not found in database')
                        
                    try:
                        #calling Virus Total to check reputation
                        vturl = 'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
                        url = vturl.format(ip = row[0])
                        headers = {'x-apikey':VT_API}
                        response = requests.get(url, headers=headers)
                        vtdata = response.json()

                        if response.status_code == 200:
                            #simplifying the JSON output for priniting the result
                            y = vtdata['data']['attributes']['last_analysis_stats']
                            
                            print('VIRUS TOTAL - Score:')
                            print('    Harmless :', y['harmless'])
                            print('    Malicious :', y['malicious'])
                            print('    Suspicious :', y['suspicious'])
                            print('    Undetected :', y['undetected'])

                        else:
                            print('VIRUS TOTAL - IP not found in database')
                            
                    except:
                        print('VIRUS TOTAL - IP not found in database')

                    try:
                        #calling Alienvault OTX to check reputation
                        avurl = 'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation'
                        url = avurl.format(ip = row[0])
                        headers = {'x-apikey':AV_API}
                        response = requests.get(url, headers=headers)
                        avdata = response.json()
                                            
                        if response.status_code == 200:
                            #simplifying the JSON output for priniting the result
                            z = avdata['reputation']                       
                            print('ALIENVAULT - Score:', z['threat_score'])
                        
                        else:
                            print('Error loading Alienvault result')
                            
                    except:
                        print('ALIEN VAULT - IP not found in Database')

        else:
            print("Enter valid CSV filename e.g: 'example.csv'")
            menu()


    def URLChecker_CSV():
        print("\n ----------------------------------- ")
        print("     U R L   R E P U T A T I O N     ")
        print(" ----------------------------------- ")

        #opening file as CSV and iteration row by row on column A
        inputFilename = input("Enter file name containing URL/Domain: ")

        if re.search(".csv", inputFilename):   
            with open(inputFilename) as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    print("\nDetails for URL/Domain:", row[0])
                    try:
                        #calling Virus Total to check reputation
                        url_id = base64.urlsafe_b64encode(row[0].encode()).decode().strip("=")

                        iurl = 'https://www.virustotal.com/api/v3/urls/{id}'
                        url = iurl.format(id = url_id)
                        headers = {'x-apikey': VT_API}
                        response = requests.get(url, headers=headers)
                        vtdata = response.json()

                        if response.status_code == 200:
                            #simplifying the JSON output for priniting the result
                            z = vtdata['data']['attributes']['categories']
                            y = vtdata['data']['attributes']['last_analysis_stats']
                            print('Categorization of URL/domain:')
                            print(*z.values(), sep =',')        
                            print('VIRUS TOTAL - Score:')
                            print('    Harmless :', y['harmless'])
                            print('    Malicious :', y['malicious'])
                            print('    Suspicious :', y['suspicious'])
                            print('    Undetected :', y['undetected'])
                            
                        else:
                            print('VIRUS TOTAL - URL/Domain not found in database')
                                
                    except:
                        print('VIRUS TOTAL - URL/Domain not found in database')

                    try:
                        #calling Alienvault OTX to check reputation
                        avurl = 'https://otx.alienvault.com/api/v1/indicators/url/{purl}/url_list'
                        url = avurl.format(purl = inputURL)
                        headers = {'x-apikey':AV_API}
                        response = requests.get(url, headers=headers)
                        avdata = response.json()
                                                    
                        if response.status_code == 200:                    
                            print('Continent Code:', avdata['continent_code'])
                            print('Country Name:', avdata['country_name'])
                                
                        else:
                            print('Error loading Alienvault result')
                            
                    except:
                        print('ALIEN VAULT - URL/domain not found in Database')

        else:
            print("Enter valid CSV filename e.g: 'example.csv'")
            menu()        


    def HashChecker_CSV():
        print("\n ----------------------------------- ")
        print("    H A S H   R E P U T A T I O N    ")
        print(" ----------------------------------- ")

        #opening file as CSV and iteration row by row on column A
        inputFilename = input("Enter file name containing Hashes: ")
        if re.search(".csv", inputFilename):
            with open(inputFilename) as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:

                    print("\nDetails for hash:", row[0])
                    try:
                        #calling Virus Total to check reputation
                        iurl = 'https://www.virustotal.com/api/v3/files/{id}'
                        url = iurl.format(id = row[0])
                        headers = {'x-apikey':VT_API}
                        response = requests.get(url, headers=headers)
                        vtdata = response.json()

                        if response.status_code == 200:                            
                            #simplifying the JSON output for priniting the result
                            x = vtdata['data']['attributes']
                            y = vtdata['data']['attributes']['last_analysis_stats']
                            
                            print('Name of file:', x['meaningful_name'])
                            try:
                                z = vtdata['data']['attributes']['signature_info']
                                
                                print('Signature info:', z['signers'])   
                                try:
                                    print('Description:', z['description'])
                                    print('Internal name:', z['internal name'])
                                    print('Signature Verification: Signed file, valid signature')
                                except:
                                    print('Signature Verification: Signed file, valid signature')
                            except:
                                print('Signature info: File not signed')
                                
                            print('VIRUS TOTAL - Score:')
                            print('    Harmless :', y['harmless'])
                            print('    Malicious :', y['malicious'])
                            print('    Suspicious :', y['suspicious'])
                            print('    Undetected :', y['undetected'])
                            
                        else:
                            print('VIRUS TOTAL - Hash not found in database')                        
                            
                    except:
                        print('VIRUS TOTAL - Hash not found in database')

        else:
            print("Enter valid CSV filename e.g: 'example.csv'")
            menu()

    def IPChecker():
        print("\n ----------------------------------- ")
        print("      I P   R E P U T A T I O N      ")
        print(" ----------------------------------- ")

        #taking input from user
        inputIP = input("Enter IP Address: ")
        regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
        if inputIP.strip() and re.search(regex, inputIP):
                        
            print("\nDetails for the IP:")
            try:    
                #calling Abuse IPDb to check reputation
                url = 'https://api.abuseipdb.com/api/v2/check'
                querystring = {
                    'ipAddress': inputIP,
                    'maxAgeInDays': '90'
                }
                headers = {
                   'Accept': 'application/json',
                   'Key': AbuseIP_API
                }
                response = requests.request(method='GET', url=url, headers=headers, params=querystring)
                decodedResponse = json.loads(response.text)

                if response.status_code == 200:
                    #simplifying the JSON output for priniting the result
                    x = decodedResponse['data']
                        
                    print('Domain Name:', x['domain'])
                    print('ISP:', x['isp'])
                    print('Country Code:', x['countryCode'])
                    print('ABUSE IPDB - Abuse confidence score:', x['abuseConfidenceScore'])

                else:
                    print('Error loading Abuse IPDB result')          
                    
            except:
                print('ABUSE IPDB - IP not found in database')
                        
            try:
                #calling Virus Total to check reputation
                vturl = 'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
                url = vturl.format(ip = inputIP)
                headers = {'x-apikey':VT_API}
                response = requests.get(url, headers=headers)
                vtdata = response.json()

                if response.status_code == 200:
                    #simplifying the JSON output for priniting the result
                    y = vtdata['data']['attributes']['last_analysis_stats']
                            
                    print('VIRUS TOTAL - Score:')
                    print('    Harmless :', y['harmless'])
                    print('    Malicious :', y['malicious'])
                    print('    Suspicious :', y['suspicious'])
                    print('    Undetected :', y['undetected'])

                else:
                    print('VIRUS TOTAL - IP not found in database')
                            
            except:
                print('VIRUS TOTAL - IP not found in database')

            try:
                #calling Alienvault OTX to check reputation
                avurl = 'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation'
                url = avurl.format(ip = inputIP)
                headers = {'x-apikey':AV_API}
                response = requests.get(url, headers=headers)
                avdata = response.json()
                                            
                if response.status_code == 200:
                    #simplifying the JSON output for priniting the result
                    z = avdata['reputation']                       
                    print('ALIENVAULT - Score:', z['threat_score'])
                        
                else:
                    print('Error loading Alienvault result')
                            
            except:
                print('ALIEN VAULT - IP not found in Database')

        else:
            print("Enter valid IP address e.g: '1.1.1.1'")
            menu()

    def URLChecker():
        print("\n ----------------------------------- ")
        print("      U R L   R E P U T A T I O N    ")
        print(" ----------------------------------- ")

        #taking input from user
        inputURL = input('Enter URL: ')
        if inputURL.strip():                           
            try:
                #calling Virus Total to check reputation
                url_id = base64.urlsafe_b64encode(inputURL.encode()).decode().strip("=")

                iurl = 'https://www.virustotal.com/api/v3/urls/{id}'
                url = iurl.format(id = url_id)
                headers = {'x-apikey': VT_API}
                response = requests.get(url, headers=headers)
                vtdata = response.json()

                if response.status_code == 200:
                    #simplifying the JSON output for priniting the result
                    z = vtdata['data']['attributes']['categories']
                    y = vtdata['data']['attributes']['last_analysis_stats']
                    print('Categorization of URL/domain:')
                    print(*z.values(), sep =',')        
                    print('VIRUS TOTAL - Score:')
                    print('    Harmless :', y['harmless'])
                    print('    Malicious :', y['malicious'])
                    print('    Suspicious :', y['suspicious'])
                    print('    Undetected :', y['undetected'])
                    
                else:
                    print('VIRUS TOTAL - URL/Domain not found in database')
                            
            except:
                print('VIRUS TOTAL - URL/Domain not found in database')

            try:
                #calling Alienvault OTX to check reputation
                avurl = 'https://otx.alienvault.com/api/v1/indicators/url/{purl}/url_list'
                url = avurl.format(purl = inputURL)
                headers = {'x-apikey':AV_API}
                response = requests.get(url, headers=headers)
                avdata = response.json()
                                            
                if response.status_code == 200:                    
                    print('Continent Code:', avdata['continent_code'])
                    print('Country Name:', avdata['country_name'])
                        
                else:
                    print('Error loading Alienvault result')
                            
            except:
                print('ALIEN VAULT - URL/domain not found in Database')

        else:
            print("Enter a valid URL/Domain")
            menu()
                   

    def HashChecker():
        print("\n ----------------------------------- ")
        print("     H A S H   R E P U T A T I O N   ")
        print(" ----------------------------------- ")

        #taking input from user
        inputHash = input('Enter Hash: ')
        if inputHash.strip():                             
            try:
                #calling Virus Total to check reputation
                iurl = 'https://www.virustotal.com/api/v3/files/{id}'
                url = iurl.format(id = inputHash)
                headers = {'x-apikey': VT_API}
                response = requests.get(url, headers=headers)
                vtdata = response.json()

                if response.status_code == 200:                            
                    #simplifying the JSON output for priniting the result
                    x = vtdata['data']['attributes']
                    y = vtdata['data']['attributes']['last_analysis_stats']
                    
                    print('Name of file:', x['meaningful_name'])
                    try:
                        z = vtdata['data']['attributes']['signature_info']
                        
                        print('Signature info:', z['signers'])   
                        try:
                            print('Description:', z['description'])
                            print('Internal name:', z['internal name'])
                            print('Signature Verification: Signed file, valid signature')
                        except:
                            print('Signature Verification: Signed file, valid signature')
                    except:
                        print('Signature info: File not signed')
                        
                    print('VIRUS TOTAL - Score:')
                    print('    Harmless :', y['harmless'])
                    print('    Malicious :', y['malicious'])
                    print('    Suspicious :', y['suspicious'])
                    print('    Undetected :', y['undetected'])
                    
                else:
                    print('VIRUS TOTAL - Hash not found in database') 
                            
            except:
                print('VIRUS TOTAL - Hash not found in database')

        else:
            print('Enter a valid Hash')
            menu()


    def menu():
        print("\nPlease select your Input method for checking reputation:")
        print("OPTION 1: Single IP")
        print("OPTION 2: Multiple IP using CSV file")
        print("OPTION 3: Single URL")
        print("OPTION 4: Multiple URL using CSV file")
        print("OPTION 5: Single File Hash")
        print("OPTION 6: Multiple File Hash using CSV file")
        print("OPTION 7: Exit REYMON")

        choice = input("Enter option number:")
    
        if choice == '1':
            IPChecker()
        if choice == '2':
            IPChecker_CSV()
        if choice == '3':
            URLChecker()
        if choice == '4':
            URLChecker_CSV()
        if choice == '5':
            HashChecker()
        if choice == '6':
            HashChecker_CSV()
        if choice == '7':
            sys.exit(0)
        else:
            menu()

    menu()

if __name__ == "__main__":
    main()
                   
