# Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks


<h2>Description</h2>
This is a demonstration project of live cyber attacks and its proper tracking (mapping) with the help of IP address, Latitude and Longitude of attackers who tries to attempt login in our fully vulnerable machine. The machine is Windows 10 Pro running in Azure Cloud Virtual Machine. 
<br />


<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 


<h2>Environments Used </h2>

- <b>Windows 10</b> (21H2)
- <b>Azure</b>
- <b>Microsoft Sentinel</b>
- <b>API ipgeolocation.io</b>

<h2>Setup Walk Through</h2>

<p align="left">

Major Steps on this project:

1. Creating an Azure Subscription ($200 free)
2. Create a Virtual Machine on Azure and turn off its firewall and windows firewall to make it vulnerable.
3. Log Analytics Workspace: It is going to store our logs in virtual machine.
4. Then we will be setting up Azure Sentinel (SIEM).
5. We will be using the powershell to transform logs from VM to store in Log Analytics Workspace. With Powershell, the logs will be opened and details will be passed to an API to get the information of latitude and longitude to determine from where the attacks are coming at the moment. So that we can map properly on the world map for better visualization.
<br />


Step 1: Creating an Azure Account <br />


visit: https://azure.microsoft.com/en-us/free/  for free credits of $200 to perform this lab.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/8357c7ba-4344-4531-80ce-0abdc61c258d)





















Subscription can be done either with the outlook or GitHub account. The form should be filled as per the requirement and there will be window showing No automatic charges and Azure will be asking for continuation of the service after the end of credit. 
![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/a63c6634-aae2-43d1-a852-4389a632aed5)












Once the sign up process gets complete, we will get directed to the dashboard of Azure.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/6eb050b4-675c-4832-90cd-94ea8319ed76)






Step 2: Creation of virtual Machine <br />

To create the virtual machine, first visit the site: https://portal.azure.com/#home
Then in the search bar type: virtual machine.
This machine will be exposed to the internet for our experiment. Go to create and click on Azure virtual Machine.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/a62df6ca-3712-4e26-87ec-4a2c8e41707c)















After that, there will be a form to fill up for the creation of virtual machine. Select the subscription base as Pay-As-You-Go. Remember that we need to delete everything after the completion of the lab so that there won’t be anything used by us in azure to make us pay later.

In the resource group section, we need to create a new resource group. In azure, resource group is logical grouping of resources in azure that shares the same lifespan. So everything we do in the lab will be under this resource group. It will make things easier to even delete later.

And we are going to use the Windows 10 Pro machine as it is one of the most generally and publicly used Operating system. 

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/c7dffa73-b139-47d9-9097-cb8013f45296)



Give a proper username and password. This username and password will be the login credential to this virtual machine later.

For now, I am using username: SIEM and Password as per the requirement of password policy. 


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/1c975df8-b507-4600-a218-2cc1cab96861)






We leave everything else as default, check the confirmation and then next> next to networking.

In the networking section, we need to define the firewall as the weakest and exposed one, so that attackers from all over the world will be attacking it, making a good picture for us to analyze at the end of this project.

So, for that, 
In the NIC network security group (this is firewall setting), we choose Advanced and click on create new.
There we can see the default rule setup for the inbound traffic.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/76626204-ceef-454b-8849-1e313586d126)



























We need to remove that default inbound rule and create one. 

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/20d4c0bf-5792-4688-bf72-618a4d86f666)




In Destination port ranges, we put * to allow all the ports. Protocol also Any to allow all the protocols. And lower the priority to 100.
name this rule as anything you want, we put ALL_IN as a name for now, does not matter. So now we have setup the inbound rules for our virtual machine.

Click review and create.












Step 3: Creation of Log Analytic Work space. <br />

We go to search box and type Log Analytics Workspace. In this workspace, we will be ingesting logs from the virtual machine. We will be creating geographic custom logs to find out where the attacks are coming from. Click on create log analytic workspace.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d7482b80-f14a-47a1-a346-dfba3d56b333)



And make sure to choose the same resource group that has been created from the SIEM lab.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/06ef08fb-23d5-469a-a81f-8e1f13f9f960)


























Step 4: Enabling ability to gather log from the virtual machine. <br />
Go to search box, search and click on Microsoft Defender for Cloud>  and then click on environment setting on the left bar. We will see the SIEMLog, the log workspace that we have created previously.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/c477ddf1-d3cc-478c-b971-e1969b832263)










Click on the workspace, and then turn Foundational CSPM on and leave servers on and SQL servers on machine turned off.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/4378a5e7-53fb-4f73-a973-a116e675d8fd)





On the left bar, click on data collection and save it.

And go to data collection on the left. Where we need to choose all events. And then again save it using the save button on the top.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/0a805724-0e62-4f05-a858-37676b3eb09d)



Then we need to go back to the log analytic workspace to connect it to the virtual machine. Click on the log workspace and then we can see the virtual machine option in the middle tab. Click it, choose the one created for this project and then click connect.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/89486a94-5bbd-4081-b43a-2521d4bb0496)




Step 5: Setting up Sentinel <br />

Go to search box like before and choose Microsoft Sentinel. Click on create and choose the log workspace from the list.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/46395492-e270-4fbb-80ec-35d09413ba7c)




Step 6: Remote login to the virtual machine <br />

First go the search box and we need to open our virtual machine to get its IP address. Open it and we will be able to see the Public IP address on the right side of the screen.





Click on start menu> go to remote desktop connection

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/7dc7e5e6-54f6-4155-b5bd-e7311d9b3496)









































Now type the public ip of the virtual machine created in azure in there. 



![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/b56f7a6b-8c7c-4d8d-9023-a1b539c259d2)











Now you need to put the username and password that you have created on the VM at the time of its first creation.

Then we need to accept the certification and the computer will get connected to the virtual machine on azure.






![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/267741bc-e2cd-418f-ae54-27464db0784e)





















We can say no to everything as we won’t need them. After the window opens, go to start menu and setup Microsoft edge first as we will need to use it.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/2b692962-493a-473f-82a1-df6bebe9dab1)




Now virtual machine is running remotely in our desktop with Microsoft edge setup.



Step 7: Viewing Logs remotely <br />

Go to start menu on your virtual machine and type Event viewer.
Under event viewer wizard, go to Windows Logs> Security
 All the events will be loaded in some time under the Security Number of events tabs.

Here, lets make a scenario of failure login (by typing wrong password) and recheck the Security events. Lets assume that someone tried to login to our desktop but failed and we will look the event report details.

To do that, from our home desktop, we will again open the remote desktop connection and put the IP address of our virtual machine. And try to login with wrong credentials. We will refresh the security events on the virtual machine and visualize the new failure login event.






![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/e8080fb0-3680-4394-b29c-c1b8570b5a10)













Now trying to login via wrong password.




![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/fa3d38a3-85f3-4425-946f-08be2d398e79)













Now lets refresh the security events on the event viewer of virtual machine and see if this attempt is updated. 

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/be79296f-2f49-4d61-8af4-072caf532c7c)




Here, we can see the audit failure. By double clicking it, we can even get the details of the IP address who tried to do this. This kind of information is what we are going to use to locate the attacker in the next step of our lab.





![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d7979c26-6738-49b7-9691-3ecf49ae64ae)





















We can also find the IP address on the bottom of this detail section. The IP of an attacker who tried to login to this system.



Step 8: Making Virtual Machine more vulnerable to collect more data of potential attackers. <br />

For this step, we will be turning off the windows defender firewall. For that just type wf.msc in the start menu of the virtual machine. > click on Windows Defender Firewall Properties. And turn the firewall state off.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/f52dca60-3a4a-4ad1-996d-1f6561ad33de)


Also turn private and public profile also off.



![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/f07fdd25-75e4-44ad-aa53-929e0d261494)








Step 9: Powershell scrpting in Virtual machine <br />
Powershell scripting to get information of security events Pass it to the API of geo location site and then use the output information from that site to put in Sentinel for graphic visualization of attacks.

Here is the PowerShell Script to get API key from ipgeoloaction.io

    # Get API key from here: https://ipgeolocation.io/

    $API_KEY      = "d4600b4efdef42b39828f5155041a457"
    $LOGFILE_NAME = "failed_rdp.log"
    $LOGFILE_PATH = "C:\Users\$($LOGFILE_NAME)"

    # This filter will be used to filter failed RDP events from Windows Event Viewer
    $XMLFilter = @'
    <QueryList> 
       <Query Id="0" Path="Security">
         <Select Path="Security">
              *[System[(EventID='4625')]]
          </Select>
    </Query>
    </QueryList> 
    '@

    <#
    This function creates a bunch of sample log files that will be used to train the
    Extract feature in Log Analytics workspace. If you don't have enough log files to
    "train" it, it will fail to extract certain fields for some reason -_-.
    We can avoid including these fake records on our map by filtering out all logs with
    a destination host of "samplehost"
    #>
    Function write-Sample-Log() {
    "latitude:47.91542,longitude:-120.60306,destinationhost:samplehost,username:fakeuser,sourcehost:24.16.97.222,state:Washington,country:United States,label:United States - 24.16.97.222,timestamp:2021-10-26 03:28:29" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-22.90906,longitude:-47.06455,destinationhost:samplehost,username:lnwbaq,sourcehost:20.195.228.49,state:Sao Paulo,country:Brazil,label:Brazil - 20.195.228.49,timestamp:2021-10-26 05:46:20" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37022,longitude:4.89517,destinationhost:samplehost,username:CSNYDER,sourcehost:89.248.165.74,state:North Holland,country:Netherlands,label:Netherlands - 89.248.165.74,timestamp:2021-10-26 06:12:56" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:40.71455,longitude:-74.00714,destinationhost:samplehost,username:ADMINISTRATOR,sourcehost:72.45.247.218,state:New York,country:United States,label:United States - 72.45.247.218,timestamp:2021-10-26 10:44:07" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:33.99762,longitude:-6.84737,destinationhost:samplehost,username:AZUREUSER,sourcehost:102.50.242.216,state:Rabat-Salé-Kénitra,country:Morocco,label:Morocco - 102.50.242.216,timestamp:2021-10-26 11:03:13" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-5.32558,longitude:100.28595,destinationhost:samplehost,username:Test,sourcehost:42.1.62.34,state:Penang,country:Malaysia,label:Malaysia - 42.1.62.34,timestamp:2021-10-26 11:04:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:41.05722,longitude:28.84926,destinationhost:samplehost,username:AZUREUSER,sourcehost:176.235.196.111,state:Istanbul,country:Turkey,label:Turkey - 176.235.196.111,timestamp:2021-10-26 11:50:47" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:55.87925,longitude:37.54691,destinationhost:samplehost,username:Test,sourcehost:87.251.67.98,state:null,country:Russia,label:Russia - 87.251.67.98,timestamp:2021-10-26 12:13:45" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:52.37018,longitude:4.87324,destinationhost:samplehost,username:AZUREUSER,sourcehost:20.86.161.127,state:North Holland,country:Netherlands,label:Netherlands - 20.86.161.127,timestamp:2021-10-26 12:33:46" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:17.49163,longitude:-88.18704,destinationhost:samplehost,username:Test,sourcehost:45.227.254.8,state:null,country:Belize,label:Belize - 45.227.254.8,timestamp:2021-10-26 13:13:25" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    "latitude:-55.88802,longitude:37.65136,destinationhost:samplehost,username:Test,sourcehost:94.232.47.130,state:Central Federal District,country:Russia,label:Russia - 94.232.47.130,timestamp:2021-10-26 14:25:33" | Out-File $LOGFILE_PATH -Append -Encoding utf8
    }

    # This block of code will create the log file if it doesn't already exist
    if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    write-Sample-Log
    }

    # Infinite Loop that keeps checking the Event Viewer logs.
    while ($true)
    {
    
    Start-Sleep -Seconds 1
    # This retrieves events from Windows EVent Viewer based on the filter
    $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction SilentlyContinue
    if ($Error) {
        #Write-Host "No Failed Logons found. Re-run script when a login has failed."
    }

    # Step through each event collected, get geolocation
    #    for the IP Address, and add new events to the custom log
    foreach ($event in $events) {


        # $event.properties[19] is the source IP address of the failed logon
        # This if-statement will proceed if the IP address exists (>= 5 is arbitrary, just saying if it's not empty)
        if ($event.properties[19].Value.Length -ge 5) {

            # Pick out fields from the event. These will be inserted into our new custom log
            $timestamp = $event.TimeCreated
            $year = $event.TimeCreated.Year

            $month = $event.TimeCreated.Month
            if ("$($event.TimeCreated.Month)".Length -eq 1) {
                $month = "0$($event.TimeCreated.Month)"
            }

            $day = $event.TimeCreated.Day
            if ("$($event.TimeCreated.Day)".Length -eq 1) {
                $day = "0$($event.TimeCreated.Day)"
            }
            
            $hour = $event.TimeCreated.Hour
            if ("$($event.TimeCreated.Hour)".Length -eq 1) {
                $hour = "0$($event.TimeCreated.Hour)"
            }

            $minute = $event.TimeCreated.Minute
            if ("$($event.TimeCreated.Minute)".Length -eq 1) {
                $minute = "0$($event.TimeCreated.Minute)"
            }


            $second = $event.TimeCreated.Second
            if ("$($event.TimeCreated.Second)".Length -eq 1) {
                $second = "0$($event.TimeCreated.Second)"
            }

            $timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"
            $eventId = $event.Id
            $destinationHost = $event.MachineName# Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceHost = $event.properties[11].Value # Workstation Name (Source)
            $sourceIp = $event.properties[19].Value # IP Address
        

            # Get the current contents of the Log file!
            $log_contents = Get-Content -Path $LOGFILE_PATH

            # Do not write to the log file if the log already exists.
            if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
            
                # Announce the gathering of geolocation data and pause for a second as to not rate-limit the API
                #Write-Host "Getting Latitude and Longitude from IP Address and writing to log" -ForegroundColor Yellow -BackgroundColor Black
                Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }
            else {
                # Entry already exists in custom log file. Do nothing, optionally, remove the # from the line below for output
                # Write-Host "Event already exists in the custom log. Skipping." -ForegroundColor Gray -BackgroundColor Black
            }
        }
    }
    }



Then open the PowerShell ISE on your virtual machine from the start menu and then file new and paste this script. Save it on the desktop as log_export

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d6fd8ad2-912b-4e01-a2c5-535153454c03)



Now to get the API key, just go to the site:  https://ipgeolocation.io/

Sign up and 

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/5e56227a-8e38-4364-bfeb-3591f1220da1)


After signing up, we can see the dashboard of Developers where there will be an API key.



![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/94104d3b-a11e-40a4-b062-4735ffcf81d8)








We need to copy that API key and then paste it in the second line of our powershell script. Then again save the logexport file of desktop.

This script will collect the login failed data pass the whole information to ipgeolocation and then gets the needed information to track an attacker and store those information in a file and then save it in the Users of c: of the virtual machine.

We can see that by running the script and looking in the Users of C: of the virtual machine. We can try re login with false credentials, the file will get updated too.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/5d18e6bd-3aac-4ee9-b8ae-37ff7508c2e8)


Step 10: Creation of Custom Log under our Azure Log Analytic Workspace <br />

Go to azure back again, go to log analytic work space and choose your workspace. SIEM in our case. And go to tables and then create sample log and then click create sample log. Choose MMA-based and then select the log file from your virtual machine. Since we are using our real machine to do this, we can copy and paste the content of our log file and save it in notepad of our own machine. To get the data. We need to save the file as failure.log.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/62cc7960-6201-4ad3-afa1-63434d0e675a)


We are doing this to upload our log file that was stored in c:/users to train how data are going to come and how to interpret data. So we are creating a new sample log file to feed in azure.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/36a2c55c-0bfb-49a5-b648-c6e28159cff8)


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d099648c-6d92-48b8-b568-9666662aa1df)


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/631975e7-a758-44ce-99f4-f07291b852dc)

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d205ce7e-bc49-433d-b334-410a1d18bd2a)


And then save your custom log.




Step 11: Viewing the logs <br />

Now you can simply go to search tab under the log workspace and view logs by clicking on logs> Then run a query according to the need. For example to view the failed attempts of login, we can simply do this query: SecurityEvent | where EventID == 4625






![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/e641ffb9-e5c3-479a-ac79-1bd937a191fe)


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/c5a6ba90-ef0c-476e-b33b-e776c16146d2)





















Step 12: Data extraction and Training <br />
For data extraction, we need latitude, longitude, username from all the detail information that are available in the log details. But all the log details have same format, so we can extract the information based upon the patterns of the data. To do that, 
expand one of the log, right click and choose extract data.

Or by running this query

    Failed_RDP_Geolocation_CL | parse RawData with * "latitude:" Latitude ",longitude:" Longitude ",destinationhost:" DestinationHost ",username:" Username ",sourcehost:" Sourcehost ",state:" State ", country:" Country ",label:" Label ",timestamp:" Timestamp | project Latitude,     Longitude, DestinationHost, Username, Sourcehost, State, Country, Label, Timestamp



![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/5cc844f6-8fdf-45a4-86d2-0db53369fe20)










We can now wait for the attackers to attack in our system to get more data for the work.















Step 13: Setting up Map in Sentinel. <br />
We go to portal.azure.com
then Microsoft Sentinel and open the virtual machine here.
The dashboard of Sentinel gets open where we can see the overview of security events that happen in our virtual machine of azure.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/e13ca9ee-9a31-456e-891f-03ce112ec578)



So to setup the geo map, Click on workbook> Add workbook
and then click on Edit

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/db2f596c-5bb1-4a7a-982f-072cbb088e26)


There will be default widgets shown in. We can remove it and then add new query based on our requirement of view. Just click of 3 dots of the widget and Remove them. Then add query.




![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/64cf71f0-c83f-44e7-bc9f-460e7786d398)






















On the query part, paste the same query that we have created to distinguish the data during data extraction. And in the visualization part, choose Map.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/131bb193-2575-4666-9860-c079ff961d32)


That green plot is my location from where I did try the login with wrong credentials.

You can always configure the map setting, specially lable to see the required data too that is present in the table.



![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/861eb7a4-55dd-4acc-9ead-3f4292774e70)









































Now we can save the workbook as a name of mapping.

Now we can wait for days or weeks to collect a lot of data and enjoy watching the plots on the map.




![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/8db5eb9c-9256-4cdd-a95a-cb872bd4629e)






The project is complete, we can always see the unauthorized login attempt access to our virtual machine and point out the location from where the attempt is done.


Step 14: Deleting resource group (Save your money :D) <br />
Now it's time to delete the resource group so there won’t be continuous charge going on which will end our free credit of $200 and azure will start charging via our credit card.

For that, just go to search box, type resource group and delete the created resource group in it.


![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/1d0fc758-370a-4ec4-a85a-58a6c9b526e3)



It will show everything that is present in the resource group which is costing our credit per time. 

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/744775c4-304c-4c88-927e-3a5ab23486a0)



It will take some time and everything will get deleted. We can also cancel the subscription by going to all services and then subscription> select the subscription you want to cancel and then > cancel subscription.

![image](https://github.com/swopnilshakya7/Azure-Sentinel-SIEM-Mapping-Live-CyberAttacks/assets/140642619/d4fc0375-7175-4ff0-ac46-70bd17ba36ca)


<h3> Disclaimer:  This project is for educational purpose only.</h3>




<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>



