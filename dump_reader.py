import os,re,sys
import datetime
import csv

def try_dump(): ##returns boolean
    if not os.path.isdir('01 results'):
        return False
    else:
        try:
            file = open('01 results/000 dump.txt','r')
            return True
        except FileNotFoundError:
            print ('dump not found. this must be your first time.')
    
def read_dump(): ##returns 2-element tuple. [0] is address, [1] is activity record
    print('found dump. reading 000 dump.txt ...')

    file = open('01 results/000 dump.txt','r',encoding='latin-1')
    curr_line = file.readline()

    client_ip_record = {}
    header = ''

    counter = 1
    while curr_line != '': 
        counter += 1
        header_pattern = ('##\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\'s\sdump\s##')
        result = ''
        if re.search(header_pattern,curr_line):
            result = re.search('##\s(.+?)\s\'s\sdump\s##',curr_line)
            header = result.group(1)
            counter += 1
            client_ip_record[header] = []
            
        if header != '' and curr_line != '\n':
            if not re.search(header_pattern,curr_line):
                client_ip_record[header].append(eval(curr_line))
                
        curr_line = file.readline()
    unique_client_ip_set = set(client_ip_record.keys())
    print('done')
    return (unique_client_ip_set,client_ip_record)

##csv module
def dump_csv():
    filename = '01 results/000csv dump.csv'
    print ('writing 000csv dump.csv ...')

    to_dump = read_dump()[1]
    
    try:
        csvfile = open(filename,'r')
    except FileNotFoundError:
        csvfile = open(filename,'w+')
            
    with open(filename,'w',newline='',encoding='latin-1') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['ip address','web activity','year','month','day','hour','minute','second','port','user-agent','http status code'])
        for key in to_dump:
            for line in to_dump[key]:
                csvrow = []
                for i in line:
                    if type(i) is datetime.datetime:
                        csvrow = csvrow + [i.year] + [i.month] + [i.day] + [i.hour] + [i.minute] + [i.second]
                    else:
                        csvrow.append(i)
                csvwriter.writerow([key]+csvrow)
    print('csv done.')
