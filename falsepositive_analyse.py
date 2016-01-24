#!/usr/bin/python

import sys, getopt
import socket
import re
import os

def main(argv):
    valid = True
    no_querystring = True
    no_media = True
    file = None
    remoteaddr = None
    useragent = None
    timerange = None
    timestart = None
    timeend = None
    host = None
    epath = None
    erule = None
    expath = None
    output = None
    categorie = None
    exstatus = None
    try:
        opts, args = getopt.getopt(argv,"hi:u:t:l:d:o:q:m:p:r:e:c:s:",["clientip=","useragent","timerange=","log=","domain=","output=","no-querystring=","no-media=","path=","exclude-rule=","exclude-path=","categorie=","exclude-status="])
    except getopt.GetoptError:
        print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] [-e <path(es)>] -o <console | file=file> -l <log file>'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h","--help"):
            print
            print 'ModSecurity False Positive Detector'
            print '==================================='
            print
            print 'With the help of this script it is possible to detect ModSecurity False Positive. Therefore you can filter a given log for different arguments.'
            print 'For further informations see the upcoming parameters and exmples'
            print
            print 'required parameters:'
            print '--------------------'
            print '-o   Specification of the output. Options console or file'
            print '     exmaple: ... -o console ...'
            print '     exmaple: ... -o file=exceptions.txt ...'
            print '-l   Specification of the input file.'
            print '     example: ... -l logs/project_x.log'
            print
            print 'additional filter parameters:'
            print '----------------------'
            print '-r   Filter via remote address'
            print '     example: ... -r 192.168.2.1'
            print '-u   Filter via user-agent'
            print '     example: ... -u firefox'
            print '-t   Filter via timestamp or a timestamp. Specification in the unix-timestamp format'
            print '     example: ... -t 12345- (start = timestamp x, end = not defined'
            print '     example: ... -t -12345 (start = not defined, end = timestamp x)'
            print '     example: ... -t 12345-54321 (start = timestamp x, end = timestamp y)'
            print '-q   Ex- or include querystrings. Default: exclude querystrings'
            print '     example: ... -q false (excludes querystrings)'
            print '     example: ... -q true (includes querystrings)'
            print '-m   Ex- or include media files. Default: exclude media files'
            print '     example: ... -m false (excludes media files)'
            print '     example: ... -m true (inlcudes media files)'
            print '-p   Specify a path'
            print '     example: ... -p /path/to/nowhere'
            print '-r   exclude rules'
            print '     example: ... -r 12345 (excludes one rule)'
            print "     example: ... -r '(12345|54321)' (excludes more rules)"
            print '-e   exclude path'
            print '     example: ... -e string (excludes one path)'
            print "     example: ... -e '(string1|string2|string3)' (excludes multiple pathes)"
            print '-s   exclude http-status'
            print '-c   define modsecurity ruleset categorie'
            print
            print 'Example:'
            print '--------'       
            print "falsepositive_analyse.py -r 192.168.2.1 -u firefox -t 1234534354-3466238468 -p /home/ -r '(12345|23412)'"
            print
            sys.exit()
        elif opt in ("-i", "--clientip"):
            remoteaddr = arg
        elif opt in ("-u", "--useragent"):
            useragent = arg
        elif opt in ("-t", "--timerange"):
            timerange = arg
        elif opt in ("-l", "--log"):
            file = arg
        elif opt in ("-d", "--domain"):
            host = arg
        elif opt in ("-o", "--output"):
            output = arg
        elif opt in ("-q", "--no-querystring"):
            qs = arg
            if qs == "true":
                no_querystring = False
            elif qs == "True":
                no_querystring = False
            elif qs == "false":
                no_querystring = True
            elif qs == "False":
                no_querystring = True
            else:
                no_querystring = True
        elif opt in ("-m", "--no-media"):
            media = arg
            if media == "true":
                no_media = False
            elif media == "True":
                no_media = False
            elif media == "false":
                no_media = True
            elif media == "False":
                no_media = True
            else:
                no_media = True
        elif opt in ("-p", "--path"):
            epath = arg
        elif opt in ("-r", "--exclude-rule"):
            erule = arg
        elif opt in ("-e", "--exclude-path"):
            expath = arg
        elif opt in ("-c", "--categorie"):
            categorie = arg
        elif opt in ("-s", "--exclude-status"):
            exstatus = arg

    # valid arguments
    req_addr = False
    req_file = False
    req_time = False
    req_output = False

    # remote address validation
    if remoteaddr != None:
        try:
            socket.inet_aton(remoteaddr)
            req_addr = True
        except socket.error:
            valid = False
            print "given remoteaddress is invalid"
            print "programm exits"
            print ""
            print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
            sys.exit()

    # timerange validation
    # default timerange
    start = 0
    end = 0
    if timerange != None:
        regexp = re.compile(r'-')
        if regexp.search(timerange) is not None:
            # starttime
            if re.compile(r'\d[0-9]*-$').search(timerange) is not None:
                start = timerange.split("-")[0]
            # endtime
            elif re.compile(r'^-\d[0-9]*').search(timerange) is not None:
                end = timerange.split("-")[1]
            # start-end
            elif re.compile(r'^\d[0-9]*-\d[0-9]*$').search(timerange) is not None:
                times = timerange.split("-")
                start = times[0]
                end = times[1]
          
            if start != 0:
                if len(start) != 4 and len(start) != 6 and len(start) != 8 and len(start) != 10 and len(start) != 12 and len(start) != 14:
                    valid = False
                    print "given timerange is invalid"
                    print "programm exits"
                    print ""
                    print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                    sys.exit()
            if end != 0:
                if  len(end) != 4 and len(end) != 6 and len(end) != 8 and len(end) != 10 and len(end) != 12 and len(end) != 14:
                    valid = False
                    print "given timerange is invalid"
                    print "programm exits"
                    print ""
                    print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                    sys.exit()
                
            try:
                start = int(start)
                end = int(end)
                req_time = True
            except:
                valid = False
                print "given timerange is invalid"
                print "programm exits"
                print ""
                print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                sys.exit()
        else:
            if len(timerange) < 4 or len(timerange) > 14:
                valid = False
                print "given timerange is invalid"
                print "programm exits"
                print ""
                print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                sys.exit
            else:
                if len(timerange) == 4 or len(timerange) == 6 or len(timerange) == 8 or len(timerange) == 10 or len(timerange) == 12 or len(timerange) == 14:
                    try:
                        start = int(timerange)
                        req_time = True
                    except:
                        valid = False
                        print "given timerange is invalid"
                        print "programm exits"
                        print ""
                        print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                        sys.exit
                else:
                        valid = False
                        print "given timerange is invalid"
                        print "programm exits"
                        print ""
                        print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                        sys.exit
    # file validation
    if file != None:
        # check if file exists
        if os.path.exists(file) == False:
            valid = False
            print "given file does not exists"
            print "programm exits"
            print ""
            print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
            sys.exit()
        else:
            # check if file equals modsec_audit.log format
            #   checks if first line equals --.*-A--
            f = open(file, 'r')
            line = f.read(14)
            if re.compile(r'^--.*-A--$').search(line) is not None:
                req_file = True
            else:
                valid = False
                print "given file does not conform to the modsecurity audit log format"
                print "programm exits"
                print ""
                print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
                sys.exit()
            f.close()

    # output validation
    if output is not None:
        # check if output starts with file or console
        if re.compile(r'^console').search(output) is not None:
            req_output = True
        elif re.compile(r'^file=').search(output) is not None:
            outputfile = output.split("=")[1]
            output = "file"
            if len(file) > 0:
                req_output = True

    if valid == False:
        sys.exit()
    
    if req_file == True:
        if req_output == True:
            exceptions = analyse(start,end,remoteaddr,host,useragent,file,no_querystring,no_media,epath,erule,expath,categorie)
            if output == "console":
                for entry in exceptions:
                    path = entry[0]
                    rules = entry[1]
                    print path+" :"
                    str_rule = ""
                    for rule in rules:
                        str_rule = str_rule+" "+rule
                    print str_rule
                    print ""
            elif output == "file":
                f = open(outputfile,'w')
                f.write('# ModSecurity Exceptions - generated by False Positive Script (by: Dennis Moers | ]init[ AG)\n\n')
                for entry in exceptions:
                    path = entry[0]
                    rules = entry[1]
                    ids = entry[2]
                    f.write('# path: '+path+'\n')
                    if len(ids) == 1:
                        f.write('# Found in log-id as seen below ... \n')
                        f.write('# The Following string can be used as vim regex, too ... \n')
                        f.write('# '+ids[0]+'\n')
                    elif len(ids) > 1:
                        vim_str = '\|'.join(str(x) for x in ids)
                        f.write('# Found in log-ids as seen below ... \n')
                        f.write('# The Following string can be used as vim regex, too ... \n')
                        f.write('# '+vim_str+'\n')
                    f.write('<LocationMatch "'+path+'">\n')
                    str_rule = ""
                    for rule in rules:
                        f.write('  SecRuleRemoveById '+rule+'\n')
                    f.write('</LocationMatch>\n\n')
                f.close()
        else:
            print "An output format must be given. Console or File=file"
            print "programm exits."
            print ""
            print 'falsepositve_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
            sys.exit()
    else:
        print "A ModSecurity Audit Log must be given."
        print "programm exits."
        print ""
        print 'falsepositive_analyse.py [-r <remoteaddress>] [-u <useragent>] [-t <timerange>] [-q <true|false>] [-m <true|false>] [-p <path>] [-r <rule(s)>] -o <console | file=file> -l <log file>'
        sys.exit()

def analyse(start,end,remoteaddr,host,useragent,file,no_querystring,no_media,epath,erule,expath,categorie):
    # convert start / end integer to string
    # [29/Oct/2013:11:29:45 +0100]
    if start is not None:
        start = str(start)
        # year only
        if len(start) == 4:
            start = start+"0000000000"
        elif len(start) == 6:
            start = start+"00000000"
        elif len(start) == 8:
            start = start+"000000"
        elif len(start) == 10:
            start = start+"0000"
        elif len(start) == 12:
            start = start+"00"
        elif len(start) == 14:
            start = start
        start = int(start)
    else:
        start = 0

    if end is not None:
        end = str(end)
        # year only
        if len(end) == 4:
            end = end+"0000000000"
        if len(end) == 6:
            end = end+"00000000"
        if len(end) == 8:
            end = end+"000000"
        if len(end) == 10:
            end = end+"0000"
        if len(end) == 12:
            end = end+"00"
        if len(end) == 14:
            end = end
        end = int(end)
    else:
        end = 99999999999999
    part = None
    logid = None
    skip = False
    cntb = 0

    path = None
    rules = []
    logids = []
    exceptions = []
    with open(file,'r') as f:
        for line in f:
            if re.compile(r'^--.*-A--$').search(line) is not None:
                part = "A"
                # Get Log-ID
                logid = line.split('--')[1].split('-')[0]
                logids.append(logid)
            if re.compile(r'^--.*-B--$').search(line) is not None:
                part = "B"
            if re.compile(r'^--.*-F--$').search(line) is not None:
                part = "F"
            if re.compile(r'^--.*-H--$').search(line) is not None:
                part = "H"
            if re.compile(r'^--.*-Z--$').search(line) is not None:
                part = "Z"
           
            # LogPart A
            if part == "A":
                # GET Timestamp
                try:
                    log_timestamp = re.search('\[(\d\d\/(Jan|Feb|Mar|Apr|May|June|July|Aug|Sep|Oct|Nov|Dec)\/\d\d\d\d\:\d\d\:\d\d\:\d\d) \+\d\d\d\d\]', line).group(1)
                    log_timestamp = convertTimestamp(log_timestamp)
                    # compare timestamp
                    if start != 0 and end != 0:
                        if log_timestamp < start or log_timestamp > end:
                            skip = True
                    elif start == 0 and end != 0:
                        if log_timestamp > end:
                            skip = True
                    elif start != 0:
                        if log_timestamp < start:
                            skip = True
                except:
                    pass

                # GET Remote Address
                try:
                    if re.compile(r'\[(\d\d\/(Jan|Feb|Mar|Apr|May|June|July|Aug|Sep|Oct|Nov|Dec)\/\d\d\d\d\:\d\d\:\d\d\:\d\d) \+\d\d\d\d\]').search(line) is not None:
                        log_remoteaddr = line.split(" ")[3]
                        # compare Remote Address
                        if remoteaddr is not None:
                            if log_remoteaddr != remoteaddr:
                                skip = True
                except:
                    pass

            # LogPart B
            if part == "B":
                if skip == False:
                    if cntb == 1:
                        # GET REQUEST / PATH
                        try:
                            path = line.split(" ")[1]
                            
                            if epath is not None:
                                my_regex = re.escape(epath)
                                if re.search(my_regex, path, re.IGNORECASE):
                                    skip = False
                                else:
                                    skip = True

                            if expath is not None:
                                my_regex = expath
                                if re.search(my_regex, path, re.IGNORECASE):
                                    skip = True
                                else:
                                    skip = False

                            # exclude querystring '?' and ";"
                            if no_querystring == True:
                                path = path.split("?")[0]
                                path = path.split(";")[0]
                            if no_media == True:
                                mpath = path.split("?")[0]
                                mpath = mpath.split(";")[0]
                                match = re.search(r'\.(css|js|png|jpg|jpeg|gif|woff)$', mpath)
                                if match:
                                    skip = True
                        except:
                            pass
                    elif cntb == 2:
                        # GET Host
                        try:
                            log_host = line.split(" ")[1]
                            if host is not None:
                                # compare host
                                if host not in log_host:
                                    skip = True
                        except:
                            pass
                    elif cntb == 3:
                        # GET User Agent
                        try:
                            log_useragent = line.split("User-Agent: ")[1]
                            if useragent is not None:
                                # if re.search(useragent,log_useragent) is None:
                                if useragent not in log_useragent:
                                    # print useragent+" : "+log_useragent
                                    skip = True
                        except:
                            pass
                    cntb=cntb+1

            # LogPart F
            if part == "F":
                if skip == False:
                    # Get Response Status
                    try:
                        if line.startswith('HTTP'):
                            if "404" in line:
                                skip = True
                    except:
                        pass

            # LogPart H
# Message: Warning. Pattern match "\\< ?script\\b" at ARGS:search_block_form. [file "/etc/httpd/modsecurity.d/activated_rules/modsecurity_crs_41_xss_attacks.conf"] [line "191"] [id "958051"] [rev "2"] [msg "Cross-site Scripting (XSS) Attack"] [data "Matched Data: <script found within ARGS:search_block_form: <script>"] [severity "CRITICAL"] [ver "OWASP_CRS/2.2.6"] [maturity "8"] [accuracy "8"] [tag "OWASP_CRS/WEB_ATTACK/XSS"] [tag "WASCTC/WASC-8"] [tag "WASCTC/WASC-22"] [tag "OWASP_TOP_10/A2"] [tag "OWASP_AppSensor/IE1"] [tag "PCI/6.5.1"]

            if part == "H":
                if skip == False:
                    if re.compile(r'^Message:').search(line) is not None:
                        if re.search('id \"(.+?)\"', line, re.IGNORECASE) is None:
                            continue
                        id = re.search('id \"(.+?)\"',line).group(1)
                        if erule is not None:
                            my_regex = erule
                            if re.search(my_regex, id, re.IGNORECASE):
                                skip = True
                            else:
                                skip = False
                                if categorie is not None:
                                    my_regex = categorie
                                    if re.search(my_regex, line, re.IGNORECASE):
                                        my_regex = "PCRE limits exceeded"
                                        if re.search(my_regex, line, re.IGNORECASE) is None:
                                            rules.append(id)
                                else:
                                    my_regex = "PCRE limits exceeded"
                                    if re.search(my_regex, line, re.IGNORECASE) is None:
                                        rules.append(id)
                        else:
                            if categorie is not None:
                                my_regex = categorie
                                if re.search(my_regex, line, re.IGNORECASE):
                                    my_regex = "PCRE limits exceeded"
                                    if re.search(my_regex, line, re.IGNORECASE) is None:
                                        rules.append(id)
                            else:
                                my_regex = "PCRE limits exceeded"
                                if re.search(my_regex, line, re.IGNORECASE) is None:
                                    rules.append(id)

            # LogPart Z
            if part == "Z":
                if skip == False:
                    if len(exceptions) == 0:
                        if path is not None:
                            # add first value to exceptions
                            if len(rules) > 0:
                                exception = [path,rules,logids]
                                exceptions.append(exception)
                    elif len(exceptions) > 0:
                        if path is not None and len(rules) > 0:
                            path_exist = False
                            global_rules = None
                            index = None
                            cnt = 0
                            # get details
                            for entry in exceptions:
                                gpath = entry[0]
                                grules = entry[1]
                                # check if path still exists in exceptions
                                if gpath == path:
                                    path_exist = True
                                    global_rules = grules
                                    index = cnt 
                                cnt = cnt+1

                            # append new data to existing data
                            if path_exist == True:
                                # check if rules still exists in global_rules
                                for rule in rules:
                                    rule_exists = False
                                    for grule in global_rules:
                                        if grule == rule:
                                            rule_exists = True
                                    # add rule to global_path if rule does not exists in global_rule
                                    if rule_exists == False:
                                        grules = exceptions[index][1]
                                        grules.append(rule)

                                # append logid to array
                                glogids = exceptions[index][2]
                                glogids.append(logid)

                            # create a new item
                            else:
                                # add new value to exceptions
                                exception = [path,rules,logids]
                                exceptions.append(exception)

                skip = False
                cntb = 0
                path = None
                rules = []
                logids = []
                exception = []

    # return
    return exceptions
    
def convertTimestamp(timestamp):
    date = timestamp.split("/")
    day = date[0]
    month_str = date[1]
    if month_str == "Jan":
        month = "01"
    if month_str == "Feb":
        month = "02"
    if month_str == "Mar":
        month = "03"
    if month_str == "Apr":
        month = "04"
    if month_str == "May":
        month = "05"
    if month_str == "June":
        month = "06"
    if month_str == "July":
        month = "07"
    if month_str == "Aug":
        month = "08"
    if month_str == "Sep":
        month = "09"
    if month_str == "Oct":
        month = "10"
    if month_str == "Nov":
        month = "11"
    if month_str == "Dec":
        month = "12"
    year = date[2]
    time = year.split(":")
    year = time[0]
    hour = time[1]
    min = time[2]
    sec = time[3]
    timestamp = year+month+day+hour+min+sec
    timestamp = int(timestamp)
    
    # return
    return timestamp

if __name__ == "__main__":
    main(sys.argv[1:])
