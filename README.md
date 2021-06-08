# AWS-Sec
Custom Tools

Init:

Setup the AWS IAM credentials - access_key and secret_key

Note: Make sure to provide programmatic access

Location - C:\Users\<Username>\.aws\credentials

[default]
aws_access_key_id = your_access_key_id
aws_secret_access_key = your_secret_access_key

For help read the link below:

https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/setup-credentials.html

-------------------------------------------------------------------------------------

Both tools can be used for Incident Response purpose.

1. Isolate Instance - In case of an abuse report or malicious activity from a particular instance.
2. CloudWatch Logs - Extract logs from CloudWatch log streams to local drive

------------------------------------------------------------------------------------

USAGE:

1. isolate_EC2_instance.py

$python isolate_EC2_instance.py

1. Isolate by ID
2. Isolate by NAME
3. Exit

Please provide your choice:

// Either choose by entering ID or Name and provide the same
// It will show the details of attached NICs and SGs with that instance and ask for a confirmation

Are you sure you want to isolate the instance? Confirm(yes/no)?:

// The tool will prompt to provide a CIDR/IP for forensic

Choose the CIDR for new security group which needs to be associated with the isolated instance.
Select from the following:

1. MY IP
2. CIDR BLOCK

Your choice:

// A new SG will be created with the supplied value and will be attached to the NIC, after removing other SGs.
// The instance will then be accessible only from the provided IP via SSH connection

2. cloudwatch_logs.py

$python cloudwatch_logs.py

=====CloudWatchLogs Console=========
1. Log Groups
2. Exit
====================================
Enter your choice:

// Select the Log Group
// It will show all the available groups 
// Select the Log Stream and it will be downloaded to the current location

------------------------------------------------------------------------------------------------------------

Please do not use this tool for malicious purposes(while having access to key pairs). This tool was made for personal use and is for educational purpose.
