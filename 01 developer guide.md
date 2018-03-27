apachelogreader developer guide
===============================

brief description
-----------------
apachelogreader is a series of scripts written in Python3 for reading apache logs, looks for signs of SQL injections, file inclusion attempts, web-shell attacks and outputs the results in several text files plus one csv file.

- main.py scans apache logs and writes output files. (.log file) -> (6 text files, 1 csv file)
- analyze_query.py takes in a query and returns a Boolean to indicate if the query contains signs of SQL injections, file inclusion attempts or web-shell attacks. (http query) -> (Boolean)
- dump_reader.py only works after main.py has been run once. it looks for a dump file (000 dump.txt), reads it, and re-creates the data sequences that are used by main.py for analysis. (None) -> (2-element tuple of one set and one dictionary)

the framework and key functions of apachelogreader is adapted and modified from https://github.com/ryanermita/apache-logs-analyzer

how to install
--------------
download main.py, analyze_query.py, dump_reader.py and place them in the same directory as your apache log file.
preferably, your apache log file has been unzipped and stands as a .log file.

how to use
----------
1. run main.py
2. look at the outputs (gathered in folder called /01 results in the same directory)
3. maybe tweak analyze_query.py to reduce false positives/reduce noise
4. run main.py again (time will be halved as main.py will read from 000 dump.txt which contains processed data)

how it works: main.py
--------------------------------------
in this section I briefly describe what main.py actually does.

main.py has 5 functions.
1- define_variables()
2- map(op,seq)
3- extract_data(pattern,filename)
4- organize_record(timestamp,activity,client_ip,client_port,client_agent,client_success,client_ip_record)
5- print_results(unique_client_ip_set,client_ip_record)

1- define_variables()
  - creates a regular expression (regex) mask to read one line entry in an apache log. 
  - doubles as a starter interface with the user as it asks for the filename for the apache log.
  - kills the script if the filename is wrong or the apache log can't be found.
  - order of growth: time: O(1) space: O(1)

2- map(op,seq)
  - takes in a sequence (seq) and applies an operation (op) on every element in the sequence
  - recursive function
  - order of growth: time: O(n) space: O(n)

3- extract_data(pattern,filename)
  - uses (filename) to reach the apache log and analyzes each entry using a regex mask (pattern)
  - iterates through apache log and creates a 2-element tuple of a set of unique ip addresses and a dictionary of web activities (client_ip_record)
  - ignores entries that contain strings indicating queries for css, images, tooltips, popups, javascript
  - iterative function
  - order of growth: time: O(n) space: O(1)
  - do note that although time complexity is linear, this function requires a longer runtime than dump_reader.py due to the number of operations required (e.g. datetime operations, string manipulations, sequence organization, etc)
  
4- organize_record(timestamp,activity,client_ip,client_port,client_agent,client_success,client_ip_record)
  - does the appending of activities matched to each unique client ip address to create a complete dictionary
  - creates a tuple (activity,timestamp,client_port,client_agent,client_success), looks through a dictionary (client_ip_record) for the right key (client_ip), and appends the tuple to the key element.
  - tuple elements:
    [0] web activity
    [1] timestamp
    [2] port
    [3] user-agent
    [4] http status code
  - order of growth: time: O(1) space: O(1)
  
5- print_results(unique_client_ip_set,client_ip_record)
  - creates output folder /01 results in the same directory
  - creates the following output files while evaluating web activities by calling in analyze_query.py:
    - 0/6 000 dump.txt by dumping the set of unique ip addresses (unique_client_ip_set) and dict of web activities per unique client (client_ip_record) into a text file.
    - 1/6 001 ip_address_list.txt by dumping the set of unique ip addresses only
    - 2/6 002 ip_address_activities.txt by dumping the dict of web activities per unique client
    - 3/6 003 sql_injections.txt by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_sqli() from analyze_query.py, writes the web activity to the text file if detect_sqli() returns True.
    - 4/6 004 file_inclusions.txt by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_fi() from analyze_query.py, writes the web activity to the text file if detect_fi() returns True.
    - 5/6 005 web_shells.txt by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_web_shell() from analyze_query.py, writes the web activity to the text file if detect_web_shell() returns True.
    - 6/6 006 combined_sqli_rfi_shells.txt calls all 3 detection modules from analyze_query.py and writes all web activities that trigger detection criteria to the text file.
    - late addition: runs dump_reader.dump_csv() that will create a csv version of 000 dump.txt.
  - order of growth: time: O(4n^2) space: O(n^2)

how it works: analyze_query.py
------------------------------
analyze_query.py contains 3 functions to detect for SQL injections, file inclusion attacks, and web shell attempts.
1- detect_sqli(query)
2- detect_fi(query)
3- detect_web_shell(query)

1- detect_sqli(query), detect_fi(query), detect_web_shell(query) -> (True if detected, False otherwise)
  - runs a query/web activity through a series of regex masks and filters respective to SQLi, file inclusion, web shells.
  - sqli regex masks adapted from https://forensics.cert.org/latk/loginspector.py
  - fi regex masks adapted from https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--Remote-File-Inclusion-Attack-Detection/
  - web shell regex masks adapted from https://github.com/emposha/PHP-Shell-Detector 
  - filters customized through trial and error to reduce false positives/increase accuracy
  
to increase accuracy/sooth dissatisfaction of results, do adjust the regex masks or filters as you see fit.

how it works: dump_reader.py
----------------------------
dump_reader looks for a dump file (000 dump.txt) and reads the file to re-create the dictionary (client_ip_record) used by main.py to write and evaluate the apache log of interest.
1- try_dump()
2- read_dump()
3- dump_csv()

1- try_dump()
  - returns True if it finds 000 dump.txt in a 01/results folder.
  - returns False otherwise
  
2- read_dump()
  - reads 000 dump.txt
  - returns 2-element tuple where [0] is unique_client_ip_set, [1] is client_ip_record
  - order of growth: time: O(n) space: O(n)
  
3- dump_csv()
  - creates a csv version of 000 dump.txt
  - columns: ip address, web activity, year, month, day, hour, minute, second, port, user-agent, http status code
  - order of growth: time: O(n) space: O(1)
