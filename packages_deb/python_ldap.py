#!/usr/bin/python3

import pwd
import grp
import os
import sys
import subprocess
import shutil
import ldap
import getpass
import math
import string
from random import choice
from time import time


LDAP_HOST = "ldap://192.168.1.40:1389"
LDAP_BASE_DN = "ou=users,dc=example,dc=org"
LDAP_ADMIN_DN = "cn=admin,dc=example,dc=org"
HOME_BASE = "/home"

def find_gid(name):
    return grp.getgrnam(name)[2]
# Creates new entry in LDAP for given user
def create_user(user, admin_pass):
    dn = 'uid=' + user['username'] + ',' + LDAP_BASE_DN
    fullname = user['firstname'] + ' ' + user['lastname']
    home_dir = HOME_BASE + '/' + user['username']
    #gid = find_gid(user['group'])
    lastchange = int(math.floor(time() / 86400))

    entry = []
    entry.extend([
        ('objectClass', ["inetOrgPerson".encode('utf-8'), "posixAccount".encode('utf-8'), "top".encode('utf-8'), "shadowAccount".encode('utf-8')]),
        ('uid', user['username'].encode('utf-8')),
        ('cn', fullname.encode('utf-8')),
        ('givenname', user['firstname'].encode('utf-8')),
        ('sn', user['lastname'].encode('utf-8')),
        ('mail', user['email'].encode('utf-8')),
        ('uidNumber', str(user['uid']).encode('utf-8')),
        ('gidNumber', str(1000).encode('utf-8')),
        ('loginShell', user['shell'].encode('utf-8')),
        ('homeDirectory', home_dir.encode('utf-8')),
        ('shadowMax', "99999".encode('utf-8')),
        ('shadowWarning', "7".encode('utf-8')),
        ('shadowLastChange', str(lastchange).encode('utf-8')),
        ('userPassword', user['password'].encode('utf-8'))
    ])

    

    ldap_conn = ldap.initialize(LDAP_HOST)
    ldap_conn.simple_bind_s(LDAP_ADMIN_DN, admin_pass)

    try:
        ldap_conn.add_s(dn, entry)
    finally:
        ldap_conn.unbind_s()
        
# Generates random initial password
def generate_password():
    chars = string.ascii_letters + string.digits
    newpasswd = ""

    for i in range(8):
        newpasswd = newpasswd + choice(chars)
    return newpasswd



# This will try to bind to LDAP with admin DN and givem password and exit
# the script with error message if it fails.
def try_ldap_bind(admin_pass):
    try:
        ldap_conn = ldap.initialize(LDAP_HOST)
    except ldap.SERVER_DOWN:
        print("Can't contact LDAP server")
        exit(4)

    try:
        ldap_conn.simple_bind_s(LDAP_ADMIN_DN, admin_pass)
    except ldap.INVALID_CREDENTIALS:
        print("This password is incorrect!")
        sys.exit(3)

    print("Authentization successful")
    print("")
    
#Get input data for user
def input_data():
    user = {}

    print("Enter some information about new user.")

    # Name and email
    user['firstname'] = input("Firstname: ")
    user['lastname'] = input("Lastname: ")
    user['email'] = input("E-mail: ")

    # Username
    user['username'] = input("Username: ")


    # UID
    uid = input("UID (or empty for generate): ")
    if (uid == ""): 
        user['uid'] = generate_uid()
    else: 
        uid = int(uid)
        user['uid'] = uid

    # Group
    user['group'] = "cn=readers,ou=users,dc=example,dc=org"


    # Login shell
    shell = input("Login shell [default is /bin/false]: ")
    user['shell'] = "/bin/bash"



    # Create www?
    www = input("Create www dir? [default is y]: ")
    if (www == 'n'):
        user['www'] = False
    elif (www == 'y' or www == ''):
        user['www'] = True
    else:
        print("You must type 'y' or 'n' or nothing for default!")
        sys.exit(1)

    # FS quota for home directory

    user['quota'] = int(1)

    print("")

    return user    

#VUlnerable query to ldap injection
def search_users(user, admin_pass):
	con = ldap.initialize(LDAP_HOST, bytes_mode=False)
	con.simple_bind_s(LDAP_ADMIN_DN, admin_pass)
	results = con.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, u"(uid="+user+"*)")
	print("execute query")
	return results
	
#vulnerable query to ldap injection
def search_groups(group, admin_pass):
	con = ldap.initialize(LDAP_HOST, bytes_mode=False)
	con.simple_bind_s(LDAP_ADMIN_DN, admin_pass)
	results = con.search_s(LDAP_BASE_DN, ldap.SCOPE_SUBTREE, u"(cn="+group+"*)")
	print("execute query")
	return results


def get_group():
	group = {}
	cn = input("enter group name: ")
	group['groupname']=cn
	member = input("enter group member : ")
	group['member']=member
	return group

def create_group(group, admin_pass):
	dn = 'cn=' + group['groupname'] + ',' + LDAP_BASE_DN
	entry=[]
	entry.extend([
        ('objectClass', ["groupOfNames".encode('utf-8')]),
	('cn', group['groupname'].encode('utf-8')),
	('member', group["member"].encode('utf-8'))])
	ldap_conn = ldap.initialize(LDAP_HOST)
	ldap_conn.simple_bind_s(LDAP_ADMIN_DN, admin_pass)
	try:
	        ldap_conn.add_s(dn, entry)
	finally:
	        ldap_conn.unbind_s()

###########################
#Main create user on LDAP
#######################
admin_pass = "adminpassword"
print("Create User python3 script ")
try_ldap_bind(admin_pass)
print("Check connection succesfully !!!")

while True:
	print("")
	print("")
	print("\t1.Search User ")
	print("\t2.Search groups ")
	print("\t3.create user ")
	print("\t4.create groups ")
	print("\t5.Exit tool \n")
	option = input("Select Operation  ")

	if(str(option) == str(3)):
		user = input_data()
		print("Create password ")
		user['password'] = generate_password()
		print("Creating LDAP entry")
		create_user(user, admin_pass)
		print("Create user succesfully !!")
		print("Account for user " + user['username'] + " (" + str(user['uid']) + ") successfuly created")
		print("Initial password is: " + user['password'])
	elif(str(option) == str(1)):
		username=input("search user ")
		try:
        		userdata=search_users(username,admin_pass)
		except KeyError:
			print("User not found "+username)
		else:
			print("User found "+username)
			print(userdata)
	elif(str(option) == str(2)):
		print("search groups ")
		group=input("search group ")
		try:
        		groupdata=search_groups(group, admin_pass)
		except KeyError:
			print("Group not found "+group)
		else:
			print("Group found "+group)
			print(groupdata)
	elif(str(option) == str(4)):
		print("create groups ")
		group=get_group()
		try:
			create_group(group, admin_pass)
		except KeyError:
			print("Create group exception ")
		else:
			print("Create Group success ")
	elif(str(option) == str(5)):
		print("\t Exiting program ....")
		break
