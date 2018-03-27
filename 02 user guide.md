apachelogreader user guide
==========================

What is apachelogreader?
------------------------
apachelogreader is a script written in Python3 for reading apache logs, looks for signs of SQL injections, file inclusion attempts, web-shell attacks and outputs the results in several text files plus one csv file. 

Installing apachelogreader
--------------------------
1. download main.py, analyze_query.py, and dump_reader.py from the master branch page.
2. place the scripts in the same directory as your apache log
3. hopefully you've unzipped your apache log and it stands as a .log file

Using apachelogreader
---------------------
1. run main.py. 
main.py does 3 things (in following order):
  1. read the apache log file
  2. run evaluation tests for SQLi/file inclusion/web-shell attacks
  3. write suspicious entries into text files and one csv file

as a user you can view the text files for what apachelogreader has found, note down the suspicious ip addresses that are logging some really suspicious activities, then head to the csv file and study the activities of these ip addresses in greater detail.

the csv file allows you to:
1. filter by ip addresses
2. filter by date/time (by year, month, day, hour, minute, second)
3. filter by http port
4. filter by http status code
5. filter by user agent

all these information, and being able to filter them, ideally allows a web admin to build a profile of suspicious activity and the actors behind them. there's much you can tell by looking into the user-agent that was used by an ip address, the speed at which some requests are sent to the server, the type of requests sent, the persistent presence of an ip address. 

the accuracy of the scans is dependent on the code written in analyze_query.py. to tweak the code, please read the developer guide.
