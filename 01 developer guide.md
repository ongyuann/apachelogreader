apachelogreader developer guide
===============================

brief description
-----------------
apachelogreader is a series of scripts written in Python3 that does the following:
1. Reads apache logs.
2. Looks for signs of SQL injections, file inclusion attempts, web-shell attacks.
3. Outputs the results in several text files plus one csv file.
---------------- 
There are 3 scripts in apachelogreader:
1. **main.py** scans apache logs and writes output files. (.log file) -> (6 text files, 1 csv file)
2. **analyze_query.py** takes in a query and returns a Boolean to indicate if the query contains signs of SQL injections, file inclusion attempts or web-shell attacks. (http query) -> (Boolean)
3. **dump_reader.py** only works after main.py has been run once. it looks for a dump file (000 dump.txt), reads it, and re-creates the data sequences that are used by main.py for analysis. (None) -> (2-element tuple of one set and one dictionary)

apachelogreader's framework and some key functions are adapted and modified from https://github.com/ryanermita/apache-logs-analyzer (indicated in the code).

how to install
--------------
1. Download main.py, analyze_query.py, dump_reader.py and place them in the same directory as your apache log file.

how to use
----------
1. Ensure that your apache log file has been unzipped and stands as a .log file.
2. Run main.py -> this will generate text and csv output for your analysis (gathered in folder called /01 results in the same directory).

If the results seem off:

3. Tweak analyze_query.py to reduce false positives/noise.

4. Run main.py again. (time will be roughly halved as main.py will read from 000 dump.txt which contains processed data)

Suggested analysis method:
1. Peruse the text files and note down the suspicious activities listed for each type of SQL injection, file inclusion, web-shell attack.
2. Note down the suspicious IP addresses, especially those that generate large volumes of traffic.
3. Go to the csv output and filter out the suspicious IP addresses, then:
    - Note down the timing of the activities, e.g. no. of requests sent per second, duration of sustained activities
    - Note down the user-agents used, e.g. certain nationalities are correlated to the type of browsers used, seriousness of attacks can also be adjudged by type of user-agent (mobile vs non-mobile browers) - although, user-agents can be spoofed.

how it works: main.py
--------------------------------------
main.py is the main driver of apachelogreader that calls in analyze_query.py and read_dump.py to read and analyze apache logs.
---------------
main.py has 5 functions:
1. **define_variables()**
    - Creates a regular expression (regex) mask to read one line entry in an apache log. 
    - Doubles as a starter interface with the user as it asks for the filename for the apache log.
    - Kills the script if the filename is wrong or the apache log can't be found.

2. **map(op,seq)**
    - Recursively takes in a sequence (seq) and applies an operation (op) on every element in the sequence.

3. **extract_data(pattern,filename)**
    - Uses (filename) to reach the apache log and analyzes each entry using a regex mask (pattern).
    - Iterates through apache log and creates a 2-element tuple of a set of unique ip addresses and a dictionary of web activities (client_ip_record).
    - Ignores entries that contain strings indicating queries for css, images, tooltips, popups, javascript.
  
4. **organize_record(timestamp,activity,client_ip,client_port,client_agent,client_success,client_ip_record)**
    - Organizes and appends web activities matched to each unique client ip address to create a complete Python dictionary.
    - Creates a tuple (activity,timestamp,client_port,client_agent,client_success), looks through a dictionary (client_ip_record) for the right key (client_ip), and appends the tuple to the key element.
    - Each tuple contains:
        - [0] web activity
        - [1] timestamp
        - [2] port
        - [3] user-agent
        - [4] http status code
    - Data structure: {'client_ip':(web activity, timestamp, port, user-agent, http status code)}
  
5. **print_results(unique_client_ip_set,client_ip_record)**
    - Creates output folder /01 results in the same directory.
    - Creates the following output files while evaluating web activities by calling in analyze_query.py:
      1. **000 dump.txt** by dumping the set of unique ip addresses (unique_client_ip_set) and dict of web activities per unique client (client_ip_record) into a text file.
      2. **001 ip_address_list.txt** by dumping the set of unique ip addresses only
      3. **002 ip_address_activities.txt** by dumping the dict of web activities per unique client
      4. **003 sql_injections.txt** by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_sqli() from analyze_query.py, writes the web activity to the text file if detect_sqli() returns True.
      5. **004 file_inclusions.txt** by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_fi() from analyze_query.py, writes the web activity to the text file if detect_fi() returns True.
      6. **005 web_shells.txt** by assessing each element for each key in the dict (client_ip_record), parsing the element through detect_web_shell() from analyze_query.py, writes the web activity to the text file if detect_web_shell() returns True.
      7. **006 combined_sqli_rfi_shells.txt** calls all 3 detection modules from analyze_query.py and writes all web activities that trigger detection criteria to the text file.
     - Late addition: runs dump_reader.dump_csv() to create a csv version of 000 dump.txt.


how it works: analyze_query.py
------------------------------
analyze_query.py contains 3 functions that detect for SQL injections, file inclusion attacks, and web shell attempts.
--------------
**detect_sqli(query), detect_fi(query), detect_web_shell(query)** -> (True if detected, False otherwise)
   - Runs a query/web activity through a series of regex masks and filters respective to SQLi, file inclusion, web shells.
   - SQL injection regex masks adapted from https://forensics.cert.org/latk/loginspector.py
   - File inclusion regex masks adapted from https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--Remote-File-Inclusion-Attack-Detection/
   - Web shell regex masks adapted from https://github.com/emposha/PHP-Shell-Detector 
   - The filters used in this function are layered on top of the regex masks to reduce false positives. They were created through trial and error, so are not 100% suitable for generic usage; for effective detection it is highly advisable to look at the output, adjust the filters accordingly, and run the script again to improve results.


how it works: dump_reader.py
----------------------------
dump_reader.py looks for a dump file (000 dump.txt) and reads the file to re-create the dictionary (client_ip_record) used by main.py to write and evaluate the apache log of interest.
------------
There are 3 functions in dump_reader.py:
1. **try_dump()**
    - Returns True if it finds 000 dump.txt in a 01/results folder.
    - Returns False otherwise
  
2. **read_dump()**
    - Reads 000 dump.txt
    - Returns 2-element tuple where [0] is unique_client_ip_set, [1] is client_ip_record
  
3. **dump_csv()**
    - Creates a csv version of 000 dump.txt
    - Columns: ip address, web activity, year, month, day, hour, minute, second, port, user-agent, http status code
    
how to contribute: implementation of further strategies for analyzing apache logs
------------
The current strategy that this script implements for apache log analysis is simply to run web queries through regular expression masks and identify suspicious activity due to tell-tale signs of SQL injections, file-inclusion attacks, and web-shell attacks. 

Possible strategies I am looking to include in near future:
1. Segmentation of activities, user agents, timing of connections, types of requests sent to profile individuals that connected to the web server.
2. Geo-tagging of ip addresses (e.g. via Python GeoIP library) for further profiling depth.
3. Identify hacking tools used via pattern recognition of requests sent to the server (e.g. sequential progression of types of requests from attempting to traverse directories to looking for web shell vulnerabilities).
