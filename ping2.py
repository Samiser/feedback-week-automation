import os
import subprocess
import sys
from collections import namedtuple

#Get users
#Store users in user array
#Get user info and store in array

#print(['192.168.0.1']['users']['D.jin']['name'])
#print(['192.168.0.1']['users']['D.jin']['rid'])
#print(['192.168.0.1']['users']['D.jin']['groups'])
#print(['192.168.0.1']['users']['D.jin']['groups']['rid'])
#print(['192.168.0.1']['users']['D.jin']['groups']['']  )
#print(['192.168.0.1']['users']['D.jin']['info'])

#print(['192.168.0.1']['groups']['Administrator']['rid'])

results = {}
#Array of users with [name][info]
#Array of groups

# rpcclient credentials
username = "test"
password = "test123"

def splitIntoDict(txt):
    d = {}

    for index, i in enumerate(txt):
        # Split name and rid into an array
        txt[index] = [txt[index][:txt[index].find("rid:")-1], txt[index][txt[index].find("rid:"):]]
        # Splice out values and store in a dictionary
        d[txt[index][0][txt[index][0].find(":[")+2:-1]] = {"name": txt[index][0][txt[index][0].find(":[")+2:-1], "rid": txt[index][1][5:-1]}
    return d

def enumAliases(host):
    command = ["rpcclient", host, "-U", username + "%" + password, "-c"]
    dicts = {"builtin": {}, "domain": {}}

    for i in dicts:
        # Enumerate aliases and rids
        dicts[i] = splitIntoDict(subprocess.run(command+["enumalsgroups " + i], encoding="ascii", stdout=subprocess.PIPE).stdout.splitlines())

    return dicts

def enumAliasMembers(host, users):
    command = ["rpcclient", host, "-U", username + "%" + password, "-c"]
    aliases = enumAliases(host)
    usrAliases = {}

    for group in aliases:
        for name in users:
            users[name]["aliases"] = {group:{}}
            # Get a list of domain aliases for that user 
            usrAliases[group] = subprocess.run(command+["queryuseraliases " + group + " " + users[name]["sid"]], encoding="ascii", stdout=subprocess.PIPE).stdout
            for alias in aliases[group]:
                if aliases[group][alias]["rid"] in usrAliases[group]:
                    # Append alias to users[name]["aliases"]
                    users[name]["aliases"][group][alias] = aliases[group][alias]

    return users

def enumGroups(host):
    command = ["rpcclient", host, "-U", username + "%" + password, "-c"]
    
    # Enumerate groups and rids
    groupsDict = splitIntoDict(subprocess.run(command+["enumdomgroups"], encoding="ascii", stdout=subprocess.PIPE).stdout.splitlines())

    return groupsDict

def enumGroupMembers(host, users):
    command = ["rpcclient", host, "-U", username + "%" + password, "-c"]
    groups = enumGroups(host)

    for name in users:
        users[name]["groups"] = {}
        # Get a list of groups for that user
        usrGroups = subprocess.run(command+["queryusergroups " + users[name]["rid"]], encoding="ascii", stdout=subprocess.PIPE).stdout

        for group in groups:
            if groups[group]["rid"] in usrGroups:
                # Append group to users[name]["aliases"]
                users[name]["groups"][group] = groups[group]

    return users

def enumUsers(host):
    command = ["rpcclient", host, "-U", username + "%" + password, "-c"]

    # Enumerate usernames and rids
    usersTxt = subprocess.run(command+["enumdomusers"], encoding="ascii", stdout=subprocess.PIPE).stdout.splitlines()
    usersDict = splitIntoDict(usersTxt)

    for name in usersDict:
        # Enumerate SID and info of each user
        usersDict[name]["rawinfo"] = subprocess.run(command+["queryuser " + usersDict[name]["rid"]], encoding="ascii", stdout=subprocess.PIPE).stdout
        usersDict[name]["sid"] = subprocess.run(command+["lookupnames " + name], encoding="ascii", stdout=subprocess.PIPE).stdout
        usersDict[name]["sid"] = usersDict[name]["sid"][usersDict[name]["sid"].find("S-"):usersDict[name]["sid"].find(" (User")]

    usersDict = enumGroupMembers(host, usersDict)
    usersDict = enumAliasMembers(host, usersDict)

    return usersDict

if __name__ == "__main__":
    hosts = sys.argv[1:]
    for host in hosts:
        print(host + ":\n\n")
        results[host] = {"users": enumUsers(host)}
        for index,user in enumerate(results[host]["users"]): 
            print("User: " + user + "\t", end="")
            if len(user) < 10:
                print("\t", end="")
            print("| SID: " + results[host]["users"][user]["sid"]) 
