import re
import boto3
from requests import get

# instance_info(id) function retrieves the information about a particular EC2 instance
# When a user tries to isolate an instance, this function will verify the details of the instance to isolate
# The function confirms the isolation request after providing all the details
# Information retrived:
# VPC ID of the VPC in which the instance is
# All the attached Network Interface cards(NICs)
# Attached security groups with those NICs
# Returns '1' is confirmation is 'yes' and '0' if 'no'

def instance_info(instance_id):
	flag=0
	client = boto3.client('ec2')
	response = client.describe_instances(InstanceIds=[instance_id])
	print("\n===============INSTANCE INFORMATION====================")
	print("\nID: ",instance_id)
	print("Name: ",response["Reservations"][0]["Instances"][0]["Tags"][0]["Value"])
	print("Type: ",response['Reservations'][0]['Instances'][0]['InstanceType'])
	print("Zone: ",response['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone'])
	print("VPC ID: ",response['Reservations'][0]['Instances'][0]['VpcId'])
	print("\n------------NETWORK AND SECURITY------------------------")
	nics = len(response['Reservations'][0]['Instances'][0]['NetworkInterfaces'])
	print("\nNICS:",nics)
	for i in range(nics):
		print("\n-----------------NIC",i+1,"-------------------------")
		print("\nNIC ID: ",response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][i]['NetworkInterfaceId'],"\n")
		sgs = len(response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][i]['Groups'])
		print("Security Groups Attached: ",sgs)
		for j in range(sgs):
			print("\nSecurity Group Name: ",response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][i]['Groups'][j]['GroupName'])
			print("Security Group Id: ",response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][i]['Groups'][j]['GroupId'])
			print("--------------------------------------------------")
	while(flag==0):
		conf = input("\nAre you sure you want to isolate the instance? Confirm(yes/no)?: ")
		conf = conf.lower()
		if(conf!='yes' and conf!='no' and conf!='y' and conf!='n' and conf!='ye'):
			print("\nWrong input")
		else:
			flag=1
			if(conf=='yes' or conf=='y' or conf=='ye'):
				return 1
			else:
				return 0

# Verifies IP Address/CIDR block which will be allowed SSH access to the instance after isolation, for Forensic purposes

def get_cidr():
	flag = 0
	cidr = ""
	while(flag==0):
		print("\nChoose the CIDR for new security group which needs to be associated with the isolated instance.\nSelect from the following:")
		print("\n1. MY IP")
		print("2. CIDR BLOCK")
		val = int(input("\nYour choice: "))
		if(val<1 or val>2):
			print("\nWrong input. Please select from the options(1 or 2)")
		elif(val==1):
			cidr = get('https://api.ipify.org').text
			cidr = cidr + "/32"
			print("\nYour IP is",cidr)
			print("Setting your IP..........")
			flag=1
			return cidr
		elif(val==2):
			cidr=check_ip(cidr)
			print("\nEntered CIDR block is",cidr)
			print("Setting your IP..........")
			flag=1
			return cidr

# Takes a CIDR block and verifies the format of the block

def check_ip(cidr):
	flag=0
	while(flag==0):
		cidr = input("\nPlease Enter the CIDR block: ")
		if(len(cidr)>18):
			print("\nWrong input. CIDR block should be of the form (0-255).(0-255).(0-255).(0-255)/(0-32)")
		else:
			check = re.match("\d{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\/\w+",cidr,re.I)
			if(check==None):
				print("\nWrong input. CIDR block should be of the form (0-255).(0-255).(0-255).(0-255)/(0-32)")
			else:
				if(cidr.count(".")==3 and cidr.count("/")==1):
					net = cidr.split(".")
					sub = net[3].split("/")
					net.pop()
					net.append(sub[0])
					net.append(sub[1])
					if(int(net[0])<0 or int(net[0])>255 or int(net[1])<0 or int(net[1])>255 or int(net[2])<0 or int(net[2])>255 or int(net[3])<0 or int(net[3])>255 or int(net[4])<0 or int(net[4])>32):
						print("\nWrong input. CIDR block should be of the form (0-255).(0-255).(0-255).(0-255)/(0-32)")
					else:
						return cidr
						flag=1
				else:
					print("Wrong input. CIDR block should be of the form (0-255).(0-255).(0-255).(0-255)/(0-32)")

# Isolating the instance by removing the Previous SGs attached to the NIC and adding a new SG 'Forensic' to the NIC
# Only SSH traffic with CIDR provided will be permitted

def isolate(instance_id,cidr):
	client = boto3.client('ec2')
	response = client.describe_instances(InstanceIds=[instance_id])
	vpc_id = response['Reservations'][0]['Instances'][0]['VpcId']
	response2 = client.create_security_group(Description="Security Group for Forensic Analysis",GroupName="Forensic",VpcId=vpc_id)
	sec_group_id = response2['GroupId']
	groups = [sec_group_id]
	response3 = client.authorize_security_group_ingress(CidrIp=cidr,GroupId=sec_group_id,FromPort=22,IpProtocol='tcp',ToPort=22)
	nics = len(response['Reservations'][0]['Instances'][0]['NetworkInterfaces'])
	for i in range(nics):
		nic_id = response['Reservations'][0]['Instances'][0]['NetworkInterfaces'][i]['NetworkInterfaceId']
		response4 = client.modify_network_interface_attribute(Groups=groups,NetworkInterfaceId=nic_id)
	return sec_group_id

# validate_instance_by_id(id)
# Takes the Instance ID provided and checks if any instance with provided ID exists
# If exist -> Provide all the details of the instance with a confirmation request. Check function 'instance_info(id)'
#		   -> Asks for IP to associate for SSH after isolation(Forensic analysis).
#		   -> Isolate the instance by removing all connected NICs
# If not exist -> 'No instance found message' and shows all the available instances
# Returns '1' after successful isolation or '0' if request was cancelled

def validate_instance_by_id(key):
	client = boto3.client('ec2')
	instances = []
	response = client.describe_instances()
	total = len(response["Reservations"])
	for i in range(total):
		instance_id = response["Reservations"][i]["Instances"][0]["InstanceId"]
		instances.append(instance_id)
		if (instance_id.lower() == key.lower()):
			val = instance_info(instance_id)
			if(val==0):
				return 0
			elif(val==1):
				cidr = get_cidr()
				group_id = isolate(instance_id.lower(),cidr)
				print("\nInstance ID :",instance_id,"has been isolated and security group 'Forensic' has been attached to it")
				print("Security Group Id -",group_id)
				print("Only SSH access from",cidr,"allowed")
				return 1
		elif(i==total-1 and instance_id.lower() != key.lower()):
			print("\nNo instance found with ID ",key)
			print("\nAvailable Instances by ID:\n")
			for j in range(len(instances)):
				print((j+1),"-",instances[j])
			return 0

# validate_instance_by_name(name)
# Takes the Instance Name provided and checks if any instance with provided Name exists
# If more than 1 with same name exists -> Ask to select ID -> Check ID by validate_instance_by_id(ID)
# If exist -> Provide all the details of the instance with a confirmation request. Check function 'instance_info(id)'
# If not exist -> 'No instance found message' and shows all the available instances
# Returns '1' after successful isolation or '0' if request was cancelled

def validate_instance_by_name(key):
	count = 0
	instances = {}
	client = boto3.client('ec2')
	response = client.describe_instances()
	total = len(response["Reservations"])
	for i in range(total):
		instance_id = response["Reservations"][i]["Instances"][0]["InstanceId"]
		instance_name = response["Reservations"][i]["Instances"][0]["Tags"][0]["Value"]
		instances[instance_id] = instance_name
		if (instance_name.lower() == key.lower()):
			count = count+1
			if(count>0 and i==total-1):
				if(count==1):
					for uid in instances.keys():
						if(instances[uid].lower()==key.lower()):
							key_id = uid
					val = instance_info(key_id)
					if(val==0):
						return 0
					elif(val==1):
						cidr = get_cidr()
						group_id = isolate(key_id,cidr)
						print("\nInstance ID :",instance_id,"has been isolated and security group 'Forensic' has been attached to it")
						print("Security Group Id -",group_id)
						print("Only SSH access from",cidr,"allowed")
						return 1
				else:
					flag = 0
					while(flag==0):
						print("\nMore than 1 instance found with the name ",key,"\n")
						for uid in instances.keys():
							if (instances[uid].lower()==key.lower()):
								print("Name :",instances[uid],"  ID :",uid)
						id_key = input("\nPlease enter the EC2 instance ID from the above list: ")
						flag = validate_instance_by_id(id_key)
					return 1
		elif(count==0 and i==total-1):
			print("\nNo instance found with NAME ",key)
			print("\nAvailable Instances by NAME:\n")
			for uid in instances.keys():
				print("Name :",instances[uid],"  ID :",uid)
			return 0
		elif(count>0 and i==total-1):
			if(count==1):
				for uid in instances.keys():
					if(instances[uid].lower()==key.lower()):
						key_id = uid
				val = instance_info(key_id)
				if(val==0):
					return 0
				elif(val==1):
					cidr = get_cidr()
					group_id = isolate(key_id,cidr)
					print("\nInstance ID :",instance_id,"has been isolated and security group 'Forensic' has been attached to it")
					print("Security Group Id -",group_id)
					print("Only SSH access from",cidr,"allowed")
					return 1
			else:
				flag = 0
				while(flag==0):
					print("\nMore than 1 instance found with the name ",key,"\n")
					for uid in instances.keys():
						if (instances[uid].lower()==key.lower()):
							print("Name :",instances[uid],"  ID :",uid)
					id_key = input("\nPlease enter the EC2 instance ID from the above list: ")
					flag = validate_instance_by_id(id_key)
				return 1


# START of the script providing a menu to select from
# After selecting '1' or '2' enter the ID or name of the instance to isolate
# Press enter if don't remember ID/Name. It will retrieve all the running instances to select from
# To exit press'3'

key = ""
choice = 0
flag = 0
while choice != 3:
	print("\n===========ISOLATE EC2 INSTANCE=================")
	print("\n1. Isolate by ID")
	print("2. Isolate by NAME")
	print("3. Exit")
	choice = int(input("\nPlease provide your choice: "))
	if(choice<1 or choice>3):
		print("\nWrong Input!! Please try again!!")
	elif(choice==1):
		while(flag==0):
			print("\n--------ISOLATE BY ID--------------")
			key = input("\nPlease specify the EC2 instance ID: ")
			if key=='exit':
				flag=1
			else:
				flag = validate_instance_by_id(key)
		flag=0
	elif(choice==2):
		while(flag==0):
			print("\n--------ISOLATE BY NAME------------")
			key = input("\nPlease specify the EC2 instance NAME: ")
			if key=='exit':
				flag=1
			else:
				flag = validate_instance_by_name(key)
		flag=0
	elif(choice==3):
		print("\nEXITING CONSOLE")