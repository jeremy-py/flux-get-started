import requests
import os
import sys, getopt
import json
import re
from time import sleep
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings (InsecureRequestWarning)

class policy:
    def __init__ (self,id,name):
        self.id = id
        self.name = name

class violation_collection:
    def __init__ (self,id,name,title,description,risk,examples):
        self.id = id
        self.name = name
        self.title = title
        self.description = description
        self.risk = risk
        self.examples = examples

class event:
    def __init__ (self,id,requestDatetime,clientIp,serverIp,serverPort,schema,host,virtualServerName,httpRequest,responseCode,policy,
                  isBlocked,hasViolations,isUnblocked,hasRequestViolations,rating,hasStagingViolations,isAlarmed,hasResponseViolations,severity,
                  all_violations):
        self.id = id
        self.requestDatetime = requestDatetime
        self.clientIp = clientIp
        self.serverIp = serverIp
        self.serverPort = serverPort
        self.schema = schema
        self.host = host
        self.virtualServerName = virtualServerName
        self.httpRequest = httpRequest
        self.responseCode = responseCode
        self.policy = policy

        self.isBlocked = isBlocked
        self.hasViolations = hasViolations
        self.isUnblocked = isUnblocked
        self.hasRequestViolations = hasRequestViolations
        self.rating = rating
        self.hasStagingViolations = hasStagingViolations
        self.isAlarmed = isAlarmed
        self.hasResponseViolations = hasResponseViolations
        self.severity = severity
   
        self.all_violations = all_violations
  
class violation:
    def __init__ (self,violation_id,violation_entityType,violation_observedEntity,violation_isBlocked,violation_isLearned,violation_isAlarmed,violation_isInStaging,violation_severity):
        self.violation_id = violation_id
        self.violation_entityType = violation_entityType
        self.violation_observedEntity = violation_observedEntity
        self.violation_observedEntity = violation_observedEntity
        self.violation_isBlocked = violation_isBlocked
        self.violation_isLearned = violation_isLearned
        self.violation_isAlarmed = violation_isAlarmed
        self.violation_isInStaging = violation_isInStaging
        self.violation_severity = violation_severity

def print_log (r,body):
    print ('\n\n------------------------- REQUEST ------------------------\n')
    print (r.url,'\n')
    print (r.request.method,' ',r.request.path_url,'\n')
    for i in r.request.headers:
        print (i, ': ', r.request.headers[i])
    print ('\n')
    print (r.request.body,'\n')

    print ('\n\n------------------------- RESPONSE ------------------------\n')
    print (r.status_code,'\n')
    for i in r.headers:
        print (i, ': ', r.headers[i])
    print ('\n\n')
    if body:
        print (r.text)
        print ('\n\n')



def get_policy_name(destination,login,password,headers,verbose):
    all_policies = []
    r = requests.get('https://' + destination + '/mgmt/tm/asm/policies', verify=False, auth=(login,password), headers=headers)
    if verbose:
        print_log(r,0)

    response_json = json.loads(r.text)
    for line in response_json["items"]:
        try:
            name = line["versionPolicyName"]
            id = line["id"]
            # Creation of a new class object
            all_policies.append(policy(id,name))
        except:
            print ('no policy found')

    return all_policies


def get_violation_collection (destination,login,password,headers,filter_srcip,verbose):
    all_violations_collection = []
    r = requests.get('https://' + destination + '/mgmt/tm/asm/violations/', verify=False, auth=(login,password), headers=headers)
   
    if verbose:
        print_log(r,1)
 
    response_json = json.loads(r.text)
    for line in response_json["items"]:
        try:
            id = line["id"]
            name = line["name"]
            title = line["title"]
            description = line["description"]
            risk = line["risk"]
            examples = line["examples"]
            all_violations_collection.append(violation_collection(id,name,title,description,risk,examples))
        except:   
            print ('violation collection error')

    return all_violations_collection


def get_events(destination,login,password,headers,filter_srcip,verbose):
    all_events = [] 
    if filter_srcip == 'no':
        r = requests.get('https://' + destination + '/mgmt/tm/asm/events/requests', verify=False, auth=(login,password), headers=headers)
    else:
        r = requests.get('https://' + destination + '/mgmt/tm/asm/events/requests?$filter=clientIp%20eq%20\'' + filter_srcip + '\'', verify=False, auth=(login,password), headers=headers)
  
    if verbose:
        print_log(r,1)

    response_json = json.loads(r.text)
    for line in response_json["items"]:
        all_violations = []
        try:
            selflink = line["selfLink"]
            id = line["id"]
            clientIp = line["clientIp"]
            serverIp = line["serverIp"]
            serverPort = line["serverPort"]
            schema = line["schema"]
            virtualServerName = line["virtualServerName"]
            host = line ["host"]
            httpRequest= line ["rawRequest"]["httpRequest"]
            requestDatetime = line ["requestDatetime"]
            responseCode = line ["responseCode"]       
            policy_tmp = line ["requestPolicyReference"]["link"]
            try:
                policy = re.search ('/asm/policies/(.+?)\?',policy_tmp).group(1)
            except:
                print ('no policy found')

            isBlocked = line["enforcementState"]["isBlocked"]
            hasViolations = line ["enforcementState"]["hasViolations"]
            isUnblocked = line ["enforcementState"]["isUnblocked"]
            hasRequestViolations = line ["enforcementState"]["hasRequestViolations"]
            rating = line ["enforcementState"]["rating"]        
            hasStagingViolations = line ["enforcementState"]["hasStagingViolations"]
            isAlarmed = line ["enforcementState"]["isAlarmed"]
            hasResponseViolations = line ["enforcementState"]["hasResponseViolations"]
            severity = line ["enforcementState"]["severity"]
           
            for violation_line in line["violations"]:
                try:
                    violation_id = re.search ('/asm/violations/(.+?)\?ver',violation_line["violationReference"]["link"]).group(1)
                    violation_entityType = violation_line["entityType"] 
                    violation_observedEntity = violation_line["observedEntity"]
                    violation_isBlocked = violation_line["enforcementState"]["isBlocked"]
                    violation_isLearned = violation_line["enforcementState"]["isLearned"]
                    violation_isAlarmed = violation_line["enforcementState"]["isAlarmed"]
                    violation_isInStaging = violation_line["enforcementState"]["isInStaging"]         
                    violation_severity = violation_line["severity"]
                 
                    all_violations.append(violation(violation_id,violation_entityType,violation_observedEntity,violation_isBlocked,violation_isLearned,violation_isAlarmed,violation_isInStaging,violation_severity))
                except:
                    print ('violation error')

            # Creation of a new class object 
            all_events.append(event(id,requestDatetime,clientIp,serverIp,serverPort,schema,host,virtualServerName,httpRequest,responseCode,policy,
                              isBlocked,hasViolations,isUnblocked,hasRequestViolations,rating,hasStagingViolations,isAlarmed,hasResponseViolations,severity,all_violations))
        
         
        except AttributeError:
            print ('Error on Event')
     
    return all_events

def display_events (all_events,all_policies,all_violations_collection):
    # v is used to count event number
    e = 1
    for i in all_events:
       # v is used to count violation number inside a event
       v = 1
       # if the event is related to a violation
       if i.hasViolations:
           print ('******************************************************************************************\n')
           print (f'************************************** EVENT {e} ****************************************\n')
           print ('******************************************************************************************\n')
           print ('---------------------- Resume --------------------\n')
           print (f'Support ID: {i.id}')       
           print (f'Date: {i.requestDatetime}')
           print (f'Severity: {i.severity}')
           print (f'Rating: {i.rating}')
           for p in all_policies:
               if i.policy == p.id:
                   print (f'Policy: {p.name}')
           print (f'\nRequest blocked: {i.isBlocked}')
           print (f'Request is alarmed: {i.isAlarmed}')
           print (f'Request has a staging violation: {i.hasStagingViolations}\n\n')
           print ('-------------------- Violations ------------------\n')
           for y in i.all_violations:
               print (f'Violation detected number: {v}')
               print (f'Severity: {y.violation_severity}')
               print (f'Type: {y.violation_entityType}')
               print (f'Detail: {y.violation_observedEntity}')
               print (f'Violation is blocked: {y.violation_isBlocked}')
               print (f'Violation is learned: {y.violation_isLearned}')
               print (f'Violation is alarmed: {y.violation_isAlarmed}')
               print (f'Violation is staging: {y.violation_isInStaging}')
               print ('\nMORE DETAILS:\n')
               # Loop to Improve...
               for z in all_violations_collection:
                   if y.violation_id == z.id:
                       print (f'Violation title: {z.title}')
                       print (f'Violation description: {z.description}')
                       print (f'Violation risk: {z.risk}')
                       print (f'Violation examples: {z.examples}')
               print ('\n\n')
               v += 1
           print ('--------------------- Request -------------------\n')
           print (f'{i.clientIp} reached {i.serverIp}:{i.serverPort} ({i.virtualServerName}) - Protocol {i.schema}\n')
           print (f'{i.httpRequest}')
           print (f'Response code: {i.responseCode}\n')
           print ('\n\n\n\n\n')
       e += 1


def usage ():
    print ('Help: request_f5.py -d <ip/domain> -l <login> -p <password> -s <srcip> -v <yes|no>')

#print (dir(r.request))
#print (r.__dict__)

def main():
    os.environ['NO_PROXY'] = '10.254.54.33'
    headers = {'user-agent': 'python/request'}
    destination = ''
    login = ''
    password = ''
    filter_srcip = 'no'
    verbose = 0
    
    try:
        opts, args = getopt.getopt(sys.argv[1:],"h:d:l:p:s:v:",["destination=","login=","password","srcip","verbose"])
    except getopt.GetoptError:
        usage ()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage ()
            sys.exit()
        elif opt in ("-d", "--destination"):
            destination = arg
        elif opt in ("-l", "--login"):
            login = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-s", "--srcip"):
            filter_srcip = arg
        elif opt in ("-v", "--verbose"):
            if arg == 'yes':
                verbose = 1
            elif arg == 'no':
                verbose = 0
            else:
                usage ()
                sys.exit()
        else:
            assert False, "unhandled option"
    
    if destination and login and password:
        print ('\nOk, let\'s go...\n')
        print ('\nGetting policies...\n')
        all_policies = get_policy_name (destination,login,password,headers,verbose)
        print ('\nGetting violation collection...\n')
        all_violations_collection = get_violation_collection (destination,login,password,headers,filter_srcip,verbose)
        print ('\nGetting filtered events....\n')
        all_events = get_events (destination,login,password,headers,filter_srcip,verbose)
        print ('\nDiplaying Output...\n')
        sleep (1) # just for display
        display_events (all_events,all_policies,all_violations_collection)
    else:
        usage ()
        sys.exit(2)

if __name__ == "__main__":
    main()
