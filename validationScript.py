#Author: Salim Ali Siddiq
#Time: Jan 2018
#!/usr/bin/python2.7
import subprocess
import filecmp
import time
import datetime

timestamp = datetime.datetime.now().strftime("%A, %d. %B %Y %I:%M%p")

#flag to keep check count
flag = 0


file = open("OriginalDaemons.txt","w")
file.write("<defunct>"+"\n")
file.write("ossec"+"\n")
file.write("-tmaster"+"\n")
file.write("/var/ossec/api/app.js"+"\n")
file.write("/var/ossec/bin/ossec-analysisd"+"\n")
file.write("/var/ossec/bin/ossec-authd"+"\n")
file.write("/var/ossec/bin/ossec-execd"+"\n")
file.write("/var/ossec/bin/ossec-logcollector"+"\n")
file.write("/var/ossec/bin/ossec-monitord"+"\n")
file.write("/var/ossec/bin/ossec-remoted"+"\n")
file.write("/var/ossec/bin/ossec-syscheckd"+"\n")
file.write("/var/ossec/bin/wazuh-clusterd"+"\n")
file.write("/var/ossec/bin/wazuh-clusterd"+"\n")
file.write("/var/ossec/bin/wazuh-clusterd"+"\n")
file.write("/var/ossec/bin/wazuh-db"+"\n")
file.write("/var/ossec/bin/wazuh-modulesd"+"\n")
file.close()



#check if syntax and semantics are correct
ps3 = subprocess.Popen(('/var/ossec/bin/ossec-logtest', '-t'), stderr=subprocess.PIPE)
ps4 = subprocess.Popen(('grep', '-i', 'error'), stdin=ps3.stderr, stdout=subprocess.PIPE)
numberOfSyntaxErrors = int(subprocess.check_output(('wc', '-l'), stdin=ps4.stdout))

print "Number Of Syntax errors: " + str(numberOfSyntaxErrors)

if numberOfSyntaxErrors == 0:

        ps6 = subprocess.Popen(('ps', '-ef'), stdout=subprocess.PIPE)
        f1 = open("OldDaemonTest.txt", "w")
#       print "writing"
        ps7 = subprocess.Popen(('grep', '-i', 'ossec'),stdin=ps6.stdout, stdout=subprocess.PIPE)
        ps8 = subprocess.Popen(["awk", "{print $NF}"], stdin=ps7.stdout, stdout=subprocess.PIPE)
        ps9 = subprocess.Popen(('sort'),stdin=ps8.stdout, stdout=f1)
#       print "written"
        ps5 = subprocess.check_output(('/var/ossec/bin/ossec-control', 'restart'), stderr=subprocess.STDOUT)

        ps10 = subprocess.Popen(('ps', '-ef'), stdout=subprocess.PIPE)
        f2 = open("NewDaemonTest.txt", "w")
#       print "writing"
        ps11 = subprocess.Popen(('grep', '-i', 'ossec'),stdin=ps10.stdout, stdout=subprocess.PIPE)
        ps12 = subprocess.Popen(["awk", "{print $NF}"], stdin=ps11.stdout, stdout=subprocess.PIPE)
        ps13 = subprocess.Popen(('sort'),stdin=ps12.stdout, stdout=f2)
#       print "written"

        time.sleep(20)

#       ps14 = subprocess.call("./validtionScript.sh")
#       print ps14

        x=filecmp.cmp('NewDaemonTest.txt','OldDaemonTest.txt')
        y=filecmp.cmp('NewDaemonTest.txt','OriginalDaemons.txt')
        if x == True and y == True:
                print "same files"
                flag = flag + 1

#       print "inside if loop"

        #check if number of agents connected is correct
        ps = subprocess.Popen(('/var/ossec/bin/agent_control', '-lc'), stdout=subprocess.PIPE)
        numberOfAgents = int(subprocess.check_output(('wc', '-l'), stdin=ps.stdout)) - 3
        print "Number of Agents registered: " + str(numberOfAgents)
        if numberOfAgents == 4:
                flag = flag + 1

        #check if number of nodes is cluster is correct
        ps1 = subprocess.Popen(('/var/ossec/bin/cluster_control', '-n'), stdout=subprocess.PIPE)
        ps2 = subprocess.Popen(('grep', '-i', 'connected'), stdin=ps1.stdout, stdout=subprocess.PIPE)
        ps14 = subprocess.Popen(('grep', '-vi', 'disconnected'), stdin=ps2.stdout, stdout=subprocess.PIPE)
        totalInCluster = int(subprocess.check_output(('wc', '-l'), stdin=ps14.stdout))
        print "Number of managers in cluster: " + str(totalInCluster)
        if totalInCluster == 3:
                flag = flag + 1

        else:
                print "failed test"

print "Test cases passed: " + str(flag)
file = open("testLogs.txt","a")
file.write("*************************************************************\n")
file.write("Time: " +timestamp + "\n")
file.write("Number of Syntax errors: " + str(numberOfSyntaxErrors) + "\n")
file.write("Number of Agents registered: " + str(numberOfAgents) + "\n")
file.write("Number of Managers in cluster: " + str(totalInCluster) + "\n")
file.close()
