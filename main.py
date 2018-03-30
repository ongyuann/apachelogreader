## code adapted from https://github.com/ryanermita/apache-logs-analyzer
## credit for functions define_variables(), extract_data(), and print_results()

import os,re,sys
import datetime
import analyze_query as aq
import dump_reader

def define_variables(): #create regex for reading apache log entries
    p = {
		's' : r'\s',					# space
		'0' : r'\d{4}-\d{2}-\d{2}',			# date
		'1' : r'\d{2}:\d{2}:\d{2}',			# time
		'2' : r'172.17.100.\d{1,3}',			# server_ip
		'3' : 'GET|POST|HEAD|OPTIONS',			# method
		'4' : '.*',					# uri_stem & query
		'5' : '80|443',					# port
		'6' : '.*',					# client_username
		'7' : r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',	# client_ip
		'8' : '.*',					# client_agent
		'9' : r'\d{3}',					# status
		'10' : r'\d{1,3}',				# substatus
		'11' : r'\d{1,3}',				# win_status
		'12' : r'\d{1,3}'                               # time_taken
        }

    pattern = ""
    for i in range(len(p)-2):
            pattern = pattern+"("+p[str(i)]+")"
            if i < len(p)-3 and i != 4:
                    pattern = pattern + p['s']
                    
    filename = input('please enter filename of apache log:\n')
    try:
        file = open(os.getcwd()+'/'+filename,'r')
    except FileNotFoundError:
        print('log doesn\'t exist or wrong filename. aborting.')
        sys.exit()
        
    extract_data(pattern,filename)

def map(op,seq): #emergency map func cos I'm unfamiliar with python's native map func
    if seq == []:
        return seq
    else:
        return [op(seq[0])] + map(op,seq[1:])

def extract_data(pattern,filename): #parse apache log and returns 2 things: set of unique ip addresses, dictionary of tuples of activities
    print('extracting data from '+ filename + ' ...')
    file = open(os.getcwd()+'/'+filename,'r',encoding='latin-1')
    client_ip_record = {}
    unique_client_ip_set = set()

    curr_line = file.readline()
    while curr_line != '':
        result = re.match(pattern,curr_line)
        if result is None:
            pass
        ##exclude css, images, javascript, jqueries, tooltips, popups
        elif any(re.findall(r'/images/|.jpg|.gif|.ico|/tooltip|popup|.css|/css|/theme/|/jquery',result.groups(0)[4],re.IGNORECASE)): 
            curr_line = file.readline()
            continue
        else:
            ddate,ttime = result.groups(0)[0].split('-'),result.groups(0)[1].split(':') #date-time
            ddate,ttime = map(lambda x:int(x),ddate),map(lambda x:int(x),ttime) #convert to integer
            timestamp = datetime.datetime(ddate[0],ddate[1],ddate[2],ttime[0],ttime[1],ttime[2])

            activity = result.groups(0)[3]+' '+result.groups(0)[4] #query
            client_ip = result.groups(0)[7] #ip address
            client_port = result.groups(0)[5]#port
            client_agent = result.groups(0)[8]#user-agent
            client_success = result.groups(0)[9] #status code
            
            unique_client_ip_set.add(client_ip)
            organize_record(timestamp,activity,client_ip,client_port,client_agent,client_success,client_ip_record)

        curr_line = file.readline()
    print('done')
    print_results(unique_client_ip_set,client_ip_record)
    
def organize_record(timestamp,activity,client_ip,client_port,client_agent,client_success,client_ip_record):
    if client_ip not in client_ip_record.keys():
            client_ip_record[client_ip] = [1,(activity,timestamp,client_port,client_agent,client_success)]
    else:
            client_ip_record[client_ip][0] = client_ip_record[client_ip][0] + 1
            ##create list of tuples for each activity
            client_ip_record[client_ip].append((activity,timestamp,client_port,client_agent,client_success))      
    return client_ip_record

#each client's record (in one tuple):
#[0] activity
#[1] timestamp
#[2] port
#[3] user-agent
#[4] http status code

##printing results (includes evaluation of server log)
def print_results(unique_client_ip_set,client_ip_record):
    print('ensuring results folder exists ... /01 results')
    if not os.path.isdir('01 results'):
        os.makedirs('01 results')
        
#000 dump ##may or may not be useful for re-analysis
    '''
    - subsequent scans can be done after tweaking the analyze_query module.
    - reading from 000 dump.txt about halves the time from extracting data from an apache log
    '''
    filename = '000 dump.txt'
    print('0/6 writing 000 dump.txt ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')
    ##note: from here on 'client_ip' is replaced by 'client' for better readability
    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        for client in unique_client_ip_set:
            file.write('\n\n## '+client+' \'s dump ##\n')
            for record in client_ip_record[client][1:]:
                file.write(str(record)+'\n')
    
#001 ip_addresses (may or may not be helpful)
    filename = '001 ip_address_list.txt'
    print('1/6 writing ' + filename + ' ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')
        
    with open(os.getcwd()+'\\01 results\\'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('#############################\n')
        file.write('## All unique ip addresses ##\n')
        file.write('#############################\n\n')
        for client in unique_client_ip_set:
            file.write(client+'\n')

#002 ip_address_activities (most helpful for manual eye-scan)
    filename = '002 ip_address_activities.txt'
    print('2/6 writing ' + filename + ' ...')    
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')

    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('##########################################\n')
        file.write('## All activities per unique ip address ##\n')
        file.write('##########################################\n\n')
        for client in unique_client_ip_set:
            file.write('## '+client+' \'s activities ##\n')
            for record in client_ip_record[client][1:]:
                file.write(record[1].strftime('%Y-%m-%d %H:%M:%S')+' '+record[2]+' '+record[4]+' '+record[0].strip(' - ')+'\n')
            file.write('\n')
    
#003 sql_injections
    filename = '003 sql_injections.txt'
    print('3/6 writing/evaluating ' + filename + ' ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')        

    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('###################################################\n')
        file.write('## Probable SQLi attempts (some false positives) ##\n')
        file.write('###################################################\n\n')
        for client in unique_client_ip_set:
            next_line = False
            to_write = []
            for record in client_ip_record[client][1:]:
                if aq.detect_sqli(record[0]):
                    #try counter for each client_ip
                    next_line = True
                    to_write.append(str((record[1].strftime('%Y-%m-%d %H:%M:%S')+' '+record[0].strip(' - '))))
            if next_line:
                file.write('## '+client+' \'s sqli attempts ##\n')
                for record in to_write:
                    file.write(record+'\n')
                file.write('\n')
    
#004 file_inclusions
    filename = '004 file_inclusions.txt'
    print('4/6 writing/evaluating ' + filename + ' ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')

    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('##########################################################################\n')
        file.write('## Probable remote/local file inclusion attempts (some false positives) ##\n')
        file.write('##########################################################################\n\n')
        for client in unique_client_ip_set:
            next_line = False
            to_write = []
            for record in client_ip_record[client][1:]:
                if aq.detect_fi(record[0]):
                    next_line = True
                    to_write.append(str((record[1].strftime('%Y-%m-%d %H:%M:%S')+' '+record[0].strip(' - '))))
            if next_line:
                file.write('## '+client+' \'s rfi/lfi attempts ##\n')
                for record in to_write:
                    file.write(record+'\n')
                file.write('\n')
    
#005 web_shells
    filename = '005 web_shells.txt'
    print('5/6 writing/evaluating ' + filename + ' ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')

    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('########################################################\n')
        file.write('## Probable web shell attempts (some false positives) ##\n')
        file.write('########################################################\n\n')
        for client in unique_client_ip_set:
            next_line = False
            to_write = []
            for record in client_ip_record[client][1:]:
                if aq.detect_web_shell(record[0]):
                    next_line = True
                    to_write.append(str((record[1].strftime('%Y-%m-%d %H:%M:%S')+' '+record[0].strip(' - '))))
            if next_line:
                file.write('## '+client+' \'s web-shell attempts ##\n')
                for record in to_write:
                    file.write(record+'\n')
                file.write('\n')

#006 combined_sqli_fi_shells (for high-level overview of suspicious activity)
    filename = '006 combined_sqli_fi_shells.txt'
    print('6/6 writing/evaluating ' + filename + ' ...')
    try:
        file = open('01 results/'+filename,'r')
    except FileNotFoundError:
        file = open('01 results/'+filename,'w+')

    with open(os.getcwd()+'/01 results/'+filename,'w',encoding='utf-8',errors='ignore') as file:
        file.write('#####################################################################\n')
        file.write('## Really suspicious actors and their activities (high-level look) ##\n')
        file.write('#####################################################################\n\n')
        for client in unique_client_ip_set:
            next_line = False
            to_write = []
            for record in client_ip_record[client][1:]:
                if aq.detect_sqli(record[0]) or aq.detect_fi(record[0]) or aq.detect_web_shell(record[0]):
                    next_line = True
                    to_write.append(str(record[1].strftime('%Y-%m-%d %H:%M:%S')+' '+record[0].strip(' - ')))
            if next_line:
                file.write('## '+client+' \'s suspicious connections ##\n')
                for record in to_write:
                    file.write(record+'\n')
                file.write('\n')
    print('done.')

##cherry-on-top csv file
    print('late addition: csv output for further analysis')
    dump_reader.dump_csv()
        
##start_script
if __name__ == '__main__':
    if dump_reader.try_dump():
        ddump = dump_reader.read_dump()
        unique_client_ip_set,client_ip_record = ddump[0],ddump[1]
        print_results(unique_client_ip_set,client_ip_record)
    else:
        define_variables()
