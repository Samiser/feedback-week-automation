import os
import subprocess
import sys
import nmap

pingResult = {}
scanner = {}

username = "test"
password = "test123"

def ping(host):
    os.system("ping -c 1 " + host + " > " + host + ".txt")
    pingFile = open(host + ".txt", 'r')
    os.system("rm " + host + ".txt")
    for num, line in enumerate(pingFile):
        if num == 1:
            if 'Unreachable' in line:
                print 'Unreachable'
                return False
            else:
                print 'Reachable'
                return True

def scan(host):
    print "Scanning " + host
    scanner[host] = nmap.PortScanner()
    scanner[host].scan(host)
    parseScan(scanner[host][host])

def parseScan(scan):
    print '\n----------\n'
    print 'Host info:\n'
    print 'IP address: {}'.format(scan['addresses']['ipv4'])
    print 'Mac address: {}'.format(scan['addresses']['mac'])
    print "\nOpen Ports:\n"
    for proto in scan.all_protocols():
        print "Protocol: {}".format(proto)
        lport = scan[proto].keys()
        lport.sort
        for port in lport:
            print "Port: {}\t".format(port),
            if scan[proto][port]['product']:
                print "Service: {}".format(scan[proto][port]['product']),
                if scan[proto][port]['version']:
                    print "Version: {}".format(scan[proto][port]['version']),
            print ""
    print "\n----------\n"

def rpcEnumDomUsers(host):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c enumdomusers > " + host + "/users.txt")
    userFile = open(host + "/users.txt")
    users = []
    for line in userFile:
        users.append(line[6:-14])
    os.system("mkdir " + host + "/users")
    for user in users:
        rpcQueryUser(host, user)

def rpcQueryUser(host, user):
    os.system("rpcclient " + host + " -U " + username + "%" + password + " -c \'queryuser \"" + user + "\"\' > " + host + "/users/\'" + user + ".txt\'")

def rpcEnumGroups(host):
    commands = ['enumdomgroups', '\'enumalsgroups builtin\'', '\'enumalsgroups domain\'']
    for i in commands:
        os.system("rpcclient " + host + " -U " + username + "%" + password + " -c " + i + " >> " + host + "/groups.txt")

def getUserGroupNames(host):
    occupiedGroups = []
    userGroupId = {}
    usersDir = os.listdir(host + "/users")
    groups = open(host + "/groups.txt", 'r')
    for user in usersDir:
        tempUserFile = open(host + "/users/" + user)
        for i, line in enumerate(tempUserFile):
            if i == 0:
                nm = line[15:-1]
            if i == 18:
                tmpid = line[12:-1]
        userGroupId[nm] = tmpid
    os.system("mkdir " + host + "/sortedUsers")
    for group in groups:
        os.system("mkdir " + host + "/sortedUsers/\'" + group[7:-14] + "\'")
        for user in userGroupId:
            if userGroupId[user] == group[-7:-2]:
                os.system("mv " + host + "/users/\'" + user + ".txt\' " + host + "/sortedUsers/\'" + group[7:-14] + "\'/")
                if group[7:-14] not in occupiedGroups:
                    occupiedGroups.append(group[7:-14])
    for group in occupiedGroups:
        os.system("mv " + host + "/sortedUsers/\'" + group + "\'" + " " + host + "/users")
    os.system("rm -r " + host + "/sortedUsers")

if __name__ == "__main__":
    hosts = sys.argv[1:]
    for host in hosts:
        if ping(host):
            print "Scanning"
            os.system("mkdir " + host)
            #scan(host)
            rpcEnumDomUsers(host)
            rpcEnumGroups(host)
            getUserGroupNames(host)
