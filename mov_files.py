#!/usr/bin/paython3

import sys
import subprocess
import ldap

LDAP_HOST = "ldap://192.168.1.40:1389"
LDAP_BASE_DN = "ou=users,dc=example,dc=org"
LDAP_ADMIN_DN = "cn=admin,dc=example,dc=org"

#vulnerable query to ldap injection
def search_groups(group, admin_pass):
	con = ldap.initialize(LDAP_HOST, bytes_mode=False)
	con.simple_bind_s(LDAP_ADMIN_DN, admin_pass)
	results = con.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, u"(cn="+group+"*)")
	print("execute query")
	return results


def search_files(user):
	print("Search all files over operative system owned by:  "+user)
	files = subprocess.getoutput("find / -user "+user+" 2>/dev/null")
	print("  ")
	print(files)
	print("\n")
	return files




##########################
#
# Main script program
############################
print("Init program move files")
print("Input number of arguments ", len(sys.argv))

if(len(sys.argv) != 4):
	print("Usage : python3 move_files.py group directory ldappassword")
else:
	group=sys.argv[1]
	directory= sys.argv[2]
	admin_pass=sys.argv[3]
	print("group: "+group)
	print("directory: "+directory)
	subprocess.call("ls -ltrh "+directory, shell=True)
	subprocess.call("mkdir "+directory+"/move_files", shell=True)
	results = search_groups(group, admin_pass)
	user_data = results[1][1]
	for usr in user_data['member']:
		print("Iterate over each users "+ str(usr))
		user= usr.decode('utf-8').split('=')[1].split(',')[0]
		files=search_files(user)
		for fileName in files.split():
			print("Move file name : "+fileName)
			subprocess.call("ls -ltrh "+fileName, shell=True)
			print("To dirrectory")
			subprocess.call("mv "+fileName+" "+directory, shell=True)
	
		
print("End program")

