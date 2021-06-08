import boto3

# Retrieve CloudWatch Logs and store in Current location

def get_log_groups():
	groups = []
	client = boto3.client('logs')
	response = client.describe_log_groups()
	total_groups = len(response["logGroups"])
	print("=========Log Groups================")
	for i in range(total_groups):
		groups.append(response["logGroups"][i]["logGroupName"])
		print(i+1,"-",groups[i])
		if(i==total_groups-1):
			print(i+2,"- Back to Main Console")
	print("===================================")
	value = int(input("Select Log Group: "))
	if(value<1 or value>total_groups+1):
		print("Wrong input!! Please try again")
		return 0
	elif(value==total_groups+1):
		return 1
	else:
		return groups[value-1]


def get_log_streams(groupname):
	stream = []
	client = boto3.client('logs')
	response = client.describe_log_streams(logGroupName=groupname)
	total_streams = len(response["logStreams"])
	print("============Log Streams===============")
	for i in range(total_streams):
		stream.append(response["logStreams"][i]["logStreamName"])
		print(i+1,"-",stream[i])
		if(i==total_streams-1):
			print(i+2,"- Back to Log Groups")
	print("======================================")
	value = int(input("Select Log Stream: "))
	if(value<1 or value>total_streams+1):
		print("Wrong input!! Please try again")
		return 0
	elif(value==total_streams+1):
		return 1
	else:
		logstream = stream[value-1]
		logs = client.get_log_events(logGroupName=groupname,logStreamName=logstream)
		total_events = len(logs["events"])
		file = open("logs.txt","w")
		for j in range(total_events):
			event = "\n"+logs["events"][j]["message"]
			file.write(event)
		file.close()


choice = 0
client = boto3.client('logs')
while choice!=2:
	print("\n=====CloudWatchLogs Console=========")
	print("1. Log Groups")
	print("2. Exit")
	print("====================================")
	choice = int(input("Enter your choice: "))
	print()
	if(choice<0 or choice>2):
		print("Wrong choice. Please try again!!")
	elif(choice==1):
		flag=1
		while(flag==1):
			ret_value=get_log_groups()
			if(ret_value==1):
				print("Back to the Main Console!!")
				flag=0
			elif(ret_value==0):
				continue
			else:
				nflag=1
				while(nflag==1):
					new_ret_value = get_log_streams(ret_value)
					if(new_ret_value==1):
						print("Back to Log Groups")
						nflag=0
					elif(new_ret_value==0):
						continue
					else:
						nflag=0
				flag=0
	else:
		print("Exiting Console!!")

