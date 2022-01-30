# Brute-Force Dection with Windows Events
# Verify if someone tried to login from external device and failed.
# Win32 API http://timgolden.me.uk/pywin32-docs/contents.html
# Logon types https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types

import win32evtlog

server = "localhost"
logtype = "Security"
flags = win32evtlog.EVENTLOG_FORWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ

def QueryEventLog(eventID, filename=None):
    logs = []
    
    h = win32evtlog.OpenBackupEventLog(server,filename)

    while True:
        events = win32evtlog.ReadEventLog(h, flags, 0)
        if events:
            for event in events:
                if event.EventID == eventID:
                    logs.append(event)
        else:
            break
    return logs

def DetectBruteForce(filename=None):
    failures = {}
    events = QueryEventLog(4625, filename)

    for event in events:
        
        if int(event.StringInserts[10]) in [3, 8, 10]:
            account = event.StringInserts[5]
            if account in failures:
                failures[account] += 1
            else:
                failures[account] = 1

    return failures

print("Address of the events log (example: events.evtx):")
filename = input()
failures = DetectBruteForce(filename)

for account in failures:
    print("TargetUserName: %s Failed logins: %s" % (account, failures[account]))
