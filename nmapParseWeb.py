def scanParse(scan):
    doc, tag, text = Doc().tagtext()

    with tag('html'):
        with tag('head'):
            with tag('title'):
                text('Nmap Results')
        with tag('body'):
            with tag('h1'):
                text('Nmap Results')

            with tag('h2'):
                text("Status:" + "\n")
            with tag('p'):
                text("Status: " + scan['status']['state'] + "\n")
            with tag('p'):    
                text("Reason: " + scan['status']['reason'] + "\n")

            with tag('h2'):
                text("Uptime:" + "\n")
            with tag('p'):
                text("Seconds: " + scan['uptime']['seconds'] + "\n")
            with tag('p'):
                text("Last Boot: " + scan['uptime']['lastboot'] + "\n")

            with tag('h2'):
                text("Addresses:" + "\n")
            with tag('p'):
                text("Mac: " + scan['addresses']['mac'] + "\n")
            with tag('p'):
                text("Ipv4: " + scan['addresses']['ipv4'] + "\n")
            
            with tag('h2'):
                text("Host Vulnerabilities: " + "\n")
            for vuln in scan['hostscript']:
                with tag('p'):
                    text(vuln['output'] + "\n")

            with tag('h2'):
                text("Ports:" + "\n")
            for port in scan['tcp']:
                with tag('p'):
                    text(str(port))
                    text("\t")
                    text(scan['tcp'][port]['name'])
                    if len(scan['tcp'][port]['name']) < 8:
                        text("\t")
                try:
                    for vuln in scan['tcp'][port]['script']:
                        if 'VULNERABLE' in scan['tcp'][port]['script'][vuln]:
                            with tag('p'):
                                text(vuln + ":" + "\n")
                            with tag('p'):
                                text(scan['tcp'][port]['script'][vuln] + "\n")
                except:
                    pass
            
            with tag('h2'):
                text("Hostnames:" + "\n")
            for hostname in scan['hostnames']:
                if hostname['type']:
                    with tag('p'):
                        text("Type: " + hostname['type'] + "\n")
                        text("Name: " + hostname['name'] + "\n")
                        text("\n")

            with tag('h2'):
                text("OS Match:" + "\n")
            for osmatch in scan['osmatch']:
                for osclass in osmatch['osclass']:
                    with tag('p'):
                        text("----------" + "\n")
                        text("Family: " + osclass['osfamily'] + "\n")
                        text("Vendor: " + osclass['vendor'] + "\n")
                        text("Type: " + osclass['type'] + "\n")
                        text("OS Generation: " + osclass['osgen'] + "\n")
                        text("Accuracy: " + osclass['accuracy'] + "\n")

f = open('test.html', 'w+')
f.write(doc.getvalue())
