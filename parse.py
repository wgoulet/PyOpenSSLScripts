import sys
import fileinput
import subprocess
import re
import os
import tempfile

# Dictionary that indicates which fields can be retrieved
# tuple in the value field consists of search string
# and a flag to indicate whether the result is on same
# line as field name or on next line(s)

certfields = {"sernum": ("Serial Number:",1),
              "subject": ("Subject",0),
              "basiccon": ("Basic Constraints",2),
              "start": ("Not Before",0),
              "end": ("Not After",0),
              "keyuse": ("Key Usage",1)}

def main():
    try:
       cert = open(sys.argv[1])
       certstr = ''
       for line in cert:
           certstr = certstr + line
       p7lines = getpkcs7(certstr)
       certlines = extractcert(p7lines)
       parselines = parsecert(certlines)
       print "Serial Number " + getfield(parselines,"sernum")
       print "Subject " + getfield(parselines,"subject")
       print "Basic Constraints " + getfield(parselines,"basiccon")
       print "Validity Start " + getfield(parselines,"start")
       print "Validity End " + getfield(parselines,"end")
       print "KeyUsages " + getfield(parselines,"keyuse")
       #body = ''
       #print body.join(parselines)
    except IOError:
       print "Unable to open " + sys.argv[1]

def getfield(inlines,field):
    pattern = certfields[field][0]
    nextline = certfields[field][1]
    linenum = 0
    for line in inlines:
        linenum += 1
        if(re.search(pattern,line)):
            if(nextline == 0):
                return line.strip()
            elif(nextline == 2):
                return line.strip() + "->" + inlines[linenum].strip()
            else:
                return inlines[linenum].strip() 
    return None

def getserial(inlines):
    linenum = 0
    for line in inlines:
        linenum += 1
        if(re.search('Serial Number:',line)):
            return inlines[linenum].strip()

def parsecert(certlines):
    output = tempfile.TemporaryFile()
    certstr = ''
    parselines = []
    certstr = certstr.join(certlines)
    proc = subprocess.Popen(["openssl","x509","-text","-certopt","no_pubkey",
        "-certopt","no_sigdump","-noout"],
        stdin=subprocess.PIPE,stdout=output)
    stderr = proc.communicate(certstr)
    output.seek(0)
    for line in output:
        parselines.append(line)
    return parselines          

def getpkcs7(instr):
    output = tempfile.TemporaryFile()
    retstr = []
    proc = subprocess.Popen(["openssl","pkcs7","-print_certs"],
        stdin=subprocess.PIPE,stdout=output)
    stderr = proc.communicate(instr)
    output.seek(0)
    for line in output:
        retstr.append(line)
    return retstr       
   
# Slurp all lines in, but discard those
# that are contained between the RSA Security 
# issuer line and the subject of the last cert in the
# chain
def extractcert(instr):
    ignore=1
    certbody = []
    for line in instr:
        #print "doing line " + line
        issueline = re.compile('issuer=') 
        if(issueline.match(line) != None):
            # simple trick to flip this bit when
            # we match this condition
            ignore=~ignore
        if(ignore == 1):
            certbody.append(line)
    return certbody
if __name__ == '__main__':
    main()
