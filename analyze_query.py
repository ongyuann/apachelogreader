# returns boolean; True if sqli/file inclusion/web shell pattern is matched. otherwise returns False.
import re

##detect sqli
def detect_sqli(query):

    #clear-text sqli attacks (high probability of false positives; customized key words used to reduce false positives)
    regex=re.compile('drop|delete|truncate|update|insert|select|declare|union|create|concat', re.IGNORECASE)
    if regex.search(query):
        if not re.search('aspectwebmedia|refund|redeemvoucher|swagbucks|inboxpound|in+a+nutshell|in a nutshell|webresource|reward|appreciation|/campaign/report|/express/',query,re.IGNORECASE):
            if re.search('and|from|where|into|by',query,re.IGNORECASE):
                return True
            elif re.search('1=|=1',query,re.IGNORECASE): 
                if re.search('user|password',query,re.IGNORECASE):
                    return True
                
    ##other regex based on https://forensics.cert.org/latk/loginspector.py           
    #single quotes, = and --
    regex=re.compile('((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', re.IGNORECASE)
    if regex.search(query):
        if not re.search('aspectwebmedia|refund|redeemvoucher|swagbucks|inboxpound|in+a+nutshell|in a nutshell|webresource|reward|appreciation|/campaign/report|/express/',query,re.IGNORECASE):
            if re.search('and|from|where|into|by',query,re.IGNORECASE):
                return True
            elif re.search('1=|=1',query,re.IGNORECASE): 
                if re.search('user|password',query,re.IGNORECASE):
                    return True       
            #return True

    #MSExec
    regex=re.compile('exec(\s|\+)+(s|x)p\w+', re.IGNORECASE)
    if regex.search(query):
        return True
 
    #hex equivalent for single quote, zero or more alphanumeric or underscore characters
    regex=re.compile('/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix', re.IGNORECASE)
    if regex.search(query):
        return True

    return False

##detect rfi
def detect_rfi(query):

    #queries with 'include', then attempt file inclusions
    regex=re.compile('include', re.IGNORECASE)
    if regex.search(query):
        if re.search('append|prepend',query,re.IGNORECASE): #more key words to reduce false positives
            return True
        elif re.search('php|cmd|dir',query,re.IGNORECASE): #more key words to reduce false positives
            return True

    #queries that attempt redirection
    regex=re.compile('go to=|goto=|file', re.IGNORECASE)
    if regex.search(query):
        if not re.search('forgotten|product|report',query,re.IGNORECASE):
            if re.search('http|.com',query,re.IGNORECASE): #more key words to reduce false positives
                return True

    #queries that attempt directory traversal
    regex=re.compile('/etc/|/../|error', re.IGNORECASE)
    if regex.search(query):
        if re.search('passwd|drivers|hosts|admin|login|account|php|aspxerrorpath|system32',query,re.IGNORECASE): #more key words to reduce false positives
            return True       

    ##other regex taken from https://www.trustwave.com/Resources/SpiderLabs-Blog/ModSecurity-Advanced-Topic-of-the-Week--Remote-File-Inclusion-Attack-Detection/
    regex=re.compile('^(?:ht|f)tps?:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', re.IGNORECASE)
    if regex.search(query):
        return True
    regex=re.compile('(?:\binclude\s*\([^)]*(ht|f)tps?:\/\/)', re.IGNORECASE)
    if regex.search(query):
        return True
    regex=re.compile('(?:ft|htt)ps?.*\?+$', re.IGNORECASE)
    if regex.search(query):
        return True
    regex=re.compile('^(?:ht|f)tps?://(.*)\?$', re.IGNORECASE)
    if regex.search(query):
        return True
    return False

##detect web shells 
def detect_web_shell(query):

    #queries that are too long
    if len(query) > 100:
        if not re.search('grouplookup|groupsearch|grouproster|sendmessage|aspectwebmedia|advanced_search|securitytoken|shippingaddress|groupleader|refund|redeemvoucher|password_forgotten|swagbucks|inboxpound|in+a+nutshell|in a nutshell|orders|webresource|product|reward|appreciation|/campaign/report|/express/|webresource',query,re.IGNORECASE): #more key words to reduce false positives
            return True

    #obvious attempts
    regex=re.compile('shell.php|webshell.php', re.IGNORECASE)
    if regex.search(query):
        return True

    #queries with '.php', with key words
    regex=re.compile('.php', re.IGNORECASE)
    if regex.search(query):
        if not re.search('refunds|groupsearch|advanced_search_result|redeemvoucher|swagbucks|inboxpound|orders|webresource|product|reward|appreciation',query,re.IGNORECASE):
            if re.search('file|manager|backup|admin|passwd|etc',query,re.IGNORECASE): #more key words to reduce false positives
                return True
            elif re.search('include|user',query,re.IGNORECASE): #more key words to reduce false positives
                return True

    ##other regex taken from https://github.com/emposha/PHP-Shell-Detector               
    regex=re.compile('%(preg_replace.*\/e|`.*?\$.*?`|\bcreate_function\b|\bpassthru\b|\bshell_exec\b|\bexec\b|\bbase64_decode\b|\bedoced_46esab\b|\beval\b|\bsystem\b|\bproc_open\b|\bpopen\b|\bcurl_exec\b|\bcurl_multi_exec\b|\bparse_ini_file\b|\bshow_source\b)%', re.IGNORECASE)
    if regex.search(query):
        return True
    return False
