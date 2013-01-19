# PyParseCert 
__version__ = '0.0.1'

import sys
import fileinput
import subprocess
import re
import os
import tempfile


__all__ = [
    'certfields',
    'getfield',
    'parsecert',
]

# Dictionary that indicates which fields can be retrieved
# tuple in the value field consists of search string
# and a flag to indicate whether the field value is on same
# line as field name or on next line(s)
certfields = {"sernum": ("Serial Number:",1),
              "subject": ("Subject",0),
              "basiccon": ("Basic Constraints",1),
              "start": ("Not Before",0),
              "end": ("Not After",0),
              "crl": ("CRL Distribution",2),
              "cps": ("Certificate Policies",2),
              "keysize": ("Public-Key",0),
              "keyuse": ("Key Usage",1)}

def _countws(instr):
    ws = re.compile('\s')
    return len(ws.findall(instr))
    
def getfield(inlines,field):
    # OpenSSL's output format is legendarily hard to parse
    # since you have to use indent level as and indicator of
    # which field a value you find belongs to. 
    pattern = certfields[field][0]
    nextline = certfields[field][1]
    linenum = 0
    for line in inlines:
        linenum += 1
        if(re.search(pattern,line)):
            if(nextline == 0):
                return line.strip()
            elif(nextline == 2):
                # Loop through next lines until we find
                # the next field that is less indented than 
                # curret line
                indent = _countws(line)
                index = linenum + 1
                currline = inlines[index]
                retstr = line.strip()
                while(_countws(currline) > indent):
                    retstr = retstr + "->" + currline.strip()
                    index += 1
                    currline = inlines[index]
                return retstr
            else:
                return inlines[linenum].strip() 

    return None

def parsecert(certlines):
    output = tempfile.TemporaryFile()
    parselines = []
    proc = subprocess.Popen(["openssl","x509","-text",
        "-certopt","no_sigdump","-noout"],
        stdin=subprocess.PIPE,stdout=output)
    stderr = proc.communicate(certlines)
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
