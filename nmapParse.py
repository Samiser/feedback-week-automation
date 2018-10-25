def scanParse(scan, f):
    log = open(f, 'wb')

    log.write("Status:" + "\n")
    log.write("Status: " + scan['status']['state'] + "\n")
    log.write("Reason: " + scan['status']['reason'] + "\n")

    log.write("\n")
    log.write("Uptime:" + "\n")
    log.write("Seconds: " + scan['uptime']['seconds'] + "\n")
    log.write("Last Boot: " + scan['uptime']['lastboot'] + "\n")

    log.write("\n")
    log.write("Addresses:" + "\n")
    log.write("Mac: " + scan['addresses']['mac'] + "\n")
    log.write("Ipv4: " + scan['addresses']['ipv4'] + "\n")

    log.write("\n")
    log.write("Host Vulnerabilities: " + "\n")
    for vuln in scan['hostscript']:
        log.write(vuln['output'] + "\n")

    log.write("\n")
    log.write("Ports:" + "\n")
    for port in scan['tcp']:
        log.write(str(port))
        log.write("\t")
        log.write(scan['tcp'][port]['name'])
        if len(scan['tcp'][port]['name']) < 8:
            log.write("\t")
        log.write("\t")
        try:
            for vuln in scan['tcp'][port]['script']:
                if 'VULNERABLE' in scan['tcp'][port]['script'][vuln]:
                    log.write(vuln + ":" + "\n")
                    log.write(scan['tcp'][port]['script'][vuln] + "\n")
        except:
            pass
        log.write("\n")
    
    log.write("\n")
    log.write("Hostnames:" + "\n")
    for hostname in scan['hostnames']:
        if hostname['type']:
            log.write("Type: " + hostname['type'] + "\n")
            log.write("Name: " + hostname['name'] + "\n")
            log.write("\n")

    log.write("\n")
    log.write("OS Match:" + "\n")
    for osmatch in scan['osmatch']:
        for osclass in osmatch['osclass']:
            log.write("----------" + "\n")
            log.write("Family: " + osclass['osfamily'] + "\n")
            log.write("Vendor: " + osclass['vendor'] + "\n")
            log.write("Type: " + osclass['type'] + "\n")
            log.write("OS Generation: " + osclass['osgen'] + "\n")
            log.write("Accuracy: " + osclass['accuracy'] + "\n")
