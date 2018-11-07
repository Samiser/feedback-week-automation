import os
import subprocess
import sys
import nmap
import cPickle as pickle
import nmapParse

# rpcclient credentials
username = "test"
password = "test123"

# returns whether host responds to ping or not
def ping(host):
    os.system("ping -c 1 " + host + " > " + host + ".txt")
    pingFile = open(host + ".txt", 'r')
    os.system("rm " + host + ".txt")
    for num, line in enumerate(pingFile):
        if num == 1:
            if 'Unreachable' in line:
                return False
            else:
                return True

def testRpc(host):
    test = os.popen("rpcclient -U " + username + "%" + password + " " + host + " -c none").read()
    if test:
        return False
    else:
        return True

# Runs an nmap scan on the host and parses using nmapParse.py
def scan(host):
    scanner = nmap.PortScanner()
    scanner.scan(host, arguments="-sV -O --script vuln")
    nmapParseWeb.scanParse(scanner[host])

# Uses rpcclient to enumerate for dom users
# Writes list of users to host/users.txt
# Runs rpcQueryUser for each user found
def rpcEnumDomUsers(host):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c enumdomusers > " + host + "/users.txt")
    userFile = open(host + "/users.txt")
    userNamesFile = open(host + "/userNames.txt", "w+")
    users = []
    for line in userFile:
        users.append(line[6:-14])
        userNamesFile.write(line[6:-14] + "\n")
    os.system("mkdir " + host + "/users")
    #for user in users:
        #rpcQueryUser(host, user)

# Uses rpcclient to enumerate info about individual users
# Writes the info to host/users/user.txt
def rpcQueryUser(host, user):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c \'queryuser \"" + user + "\"\' > " + host + "/users/\'" + user + ".txt\'")

# Uses rpcclient to enumerate for all group types
# Writes the groups to host/groups.txt
def rpcEnumGroups(host):
    commands = ['enumdomgroups']
    for i in commands:
        os.system("rpcclient " + host + " -U " + username + "%" + password + " -c " + i + " >> " + host + "/groups.txt")

# Sorts user txt files into folders of their respective groups
def getUserGroupNames(host):
    occupiedGroups = []
    userId = {}
    groups = open(host + "/groups.txt", 'r')

    # Populates userId dict with the users and their group ids
    tempUserFile = open(host + "/users.txt")
    for line in tempUserFile:
        userId[line[line.find("rid:") + 5:-2]] = line[6: line.find("] rid")]

    # Creates a directory to sort the users into
    os.system("mkdir " + host + "/sortedUsers")

    # For each group
    for group in groups:
        # Make a folder of that groups name
        os.system("mkdir " + host + "/sortedUsers/\'" + group[7:-14] + "\'")
        # Group lookup to find member rids
        rids = os.popen("rpcclient -U " + username + "%" + password + " " + host + " -c 'querygroupmem " + group[group.find("rid:[") + 5:-2] + "'").read()
        # Pull member rids into an array
        rids = rids.splitlines()
        for line in rids:
            try:
                os.system("rpcclient -U " + username + "%" + password + " " + host + " -c 'queryuser " + line[6:-12] + "'" + " > " + host + "/sortedUsers/\'" + group[7:-14] + "\'/\'" + userId[line[6:-12]] + ".txt\'")
            except:
                pass
            if group[7:-14] not in occupiedGroups:
                occupiedGroups.append(group[7:-14])
                    
    # For all occupied groups
    for group in occupiedGroups:
        # Move the groups folder to host/users
        os.system("mv " + host + "/sortedUsers/\'" + group + "\'" + " " + host + "/users")
    # Remove unoccupied folders
    os.system("rm -r " + host + "/sortedUsers")

if __name__ == "__main__":
    hosts = sys.argv[1:]
    for host in hosts:
        print "\nEnumerating " + host + "\n"
        if ping(host):
            print "Ping successful!"
            os.system("mkdir " + host)
            print "Nmap scanning..."
            scan(host)
            if testRpc(host):
                print "Rpcclient connection established"
                print "Enumerating users"
                rpcEnumDomUsers(host)
                print "Enumerating groups"
                rpcEnumGroups(host)
                print "Sorting users by group"
                getUserGroupNames(host)
            else:
                print "Cannot connect with rpcclient"
        else:
            print "Ping failed"
