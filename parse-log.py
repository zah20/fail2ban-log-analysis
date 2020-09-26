#!/usr/bin/python3
import matplotlib.pyplot as plt
import sys, subprocess, os, time
from geolite2 import geolite2

##################################################
# Program:       parse-log.py
# License:       GPLv3
# Author:        zah20
#
# Last Modified: Sat Sep 26, 2020 (02:00 PM)
# 
# Installation: 
# pip3 install python-geoip python-geoip-geolite2
#
##################################################


##################################################
#               Global Variables
##################################################

global record, tmp_outfile, tmp_data, process_data, geo, \
   iplookup_url, save_file, check_online, version

version = '0.10'

# Set this to True if you want to enable online lookup
# Not recommended if you big log with many IPs
check_online = False

# Bash processed file with semi processed data
tmp_outfile = '/tmp/test.log'

tmp_data = [] # Raw, unprocessed data 

save_file = 'output.txt'

# Each record object contains tuple (ip, date, time, country)
record = [] # Fully processed data

iplookup_url = 'https://ipapi.co/'


##################################################
#               Data Processing 
##################################################

def format_fail2ban_log(input_filename='', output_filename=''):
    # Parses fail2ban.log file using awk

    if (input_filename != '' and output_filename != ''):
        run_cmd(['cat %s | grep Found | \
                 awk \'{print $8" > "$10" > "$11}\' > %s' % \
                 (input_filename, output_filename)])


def get_country_count(data=[]):
    # Gets counts by country

    global save_file

    count_by_country = []

    formatted_data = format_list_to_country_count(data)

    return formatted_data


def format_list_to_country_count(list_input = []):
    # Formats list_input to [country, count]
    # [ip, data, time, country] -> [country,count]

    if (list_input != []):
        list_current = []

        list_current.append([list_input[0][3], 1])

        for i in list_input[1:]:
            search_result = search_list(list_current, i[3])

            if ( search_result == None ):
                list_current.append([i[3], 1])
            else:
                list_current[search_result][1] = \
                    (list_current[search_result][1]+1)
            
        return list_current
    else:
        return None
    

def sort_country_count(list_input=[], n=10):
    # Sorts data by count (descending order) 
    # list_input -> [country,count]
    # returns top n number of values, specified by n

    _list_input = sorted(list_input, key=lambda x: x[1], \
                         reverse=True)

    return _list_input[:n]


def search_list(list_input=[], val=None):
    # Searches list_input for val
    # Returns index of first match, or None if no match found
    # list_input -> [country, count]
    # Used by: format_list_to_country_count()

    if (val != None and list_input != []):
        for i in range(len(list_input)):
            if (list_input[i][0] == val):
                return i

    return None


def format_list_to_date_count(data=[]):
    # Convert data to (date, count) e.g: ('09-09', 3)
    # data = (ip, date, time, country) -> (date,count)
    # Used by: plot_time_analysis()
    
    if ( data == [] ):
        return None
    
    _data = []

    _data.append([data[0][1], 1])

    for i in data[1:]:
        result = search_list2(_data, i[1])

        if ( result == None ):
            _data.append([i[1], 1])
        else:
            _data[result][1] = (_data[result][1] + 1)

    _data = fix_date(_data)

    return _data

    
def search_list2(list_input=[], val=None):
    # Searches list_input for val
    # Returns index of first match, or None if no match found
    # list_input -> [date, count]
    # Used by: format_list_to_date_count()

    if (val != None and list_input != []):
        for i in range(len(list_input)):
            if (list_input[i][0] == val):
                return i

    return None


def fix_date(data=[]):
    # Discards year from data & sorts it in ascending order
    # E.g: data = ('2020-10-10', 1) -> ('10-10', 1)

    _data = data

    for i in range(len(_data)):
        t = _data[i][0].split('-')
        j = '%s-%s' % (t[1], t[2])

        _data[i][0] = j

    _data = sorted(_data, key=lambda x: x[0], reverse=False)

    return _data


def read_file_format_data(filename=''):
    # Loads data from file & returns a list, trims whitespace 
    data = load_file(filename)

    tmp = []

    for i in range(len(data)):
        tmp.append(data[i].strip().split(','))

    return tmp 


def process_data():
    global tmp_data, tmp_outfile, record, check_online

    iplookup = geolite2.reader()

    tmp_data = load_file(tmp_outfile)

    for i in tmp_data:
        i = i.split('>')

        # Stripping extra whitespace
        for j in range(len(i)):
            i[j] = i[j].strip()

        date = i[1]
        time = i[2]
        ip   = i[0]

        country = iplookup.get(ip)

        if country != None:
            try:
                country = iplookup.get(ip)['country']['iso_code']
            except (BaseException):
                if (check_online != False):
                    try:
                       country = iplookup_online(ip)
                    except (BaseException):
                        country = 'Unknown'
                else:
                    country = 'Unknown'
        else:
            try:
               country = iplookup_online(ip)
            except (BaseException):
                country = 'Unknown'

        new_data = (ip, date, time, country)
        record.append(new_data)


def iplookup_online(ip_addr):
    global iplookup_url, check_online

    if check_online == False:
        return 'Unknown'
    else:
        stdout, stderr = run_cmd('curl %s%s/country' % \
                                 (iplookup_url, ip_addr))

        return stdout.strip()
    

def print_data():
    global record

    for i in record:
        print(i)


##################################################
#               Data Visualization 
##################################################

def plot_bar(data=[], out_file=''):
    # Plots provided data, format [label, value]

    if ( data == [] or out_file == '' ):
        return False

    _data = sort_country_count(get_country_count(data))

    label = []
    value = []

    for i in range(len(_data)):
        label.append(_data[i][0])
        value.append(_data[i][1])

    plt.title('SSH attacks by country')
    barlist = plt.bar(label, value, width=0.5)

    # Default color for all labels 
    for i in range(len(barlist)):
        barlist[i].set_color('orange')

    # Color for Max value
    barlist[value.index(max(value))].set_color('red')

    plt.ylabel('Frequency of attacks')
    plt.xlabel('Country')

    plt.savefig(out_file)
    plt.close()

    return True


def plot_time_analysis(data=[], out_file=''):
    # Plots line chart using based on input data
    # data = (ip, date, time, country)

    if ( data == [] or out_file == '' ):
        return False

    _data = format_list_to_date_count(data)

    label = []
    value = []

    for i in range(len(_data)):
        label.append(_data[i][0])
        value.append(_data[i][1])


    plt.title('SSH attack analysis')
    plt.plot(label, value, color='red')
    plt.ylabel('Frequency of attacks')
    plt.xlabel('Timeline')

    if (len(label) >= 4):
        plt.xticks([0, (len(label)/4), (len(label)/2), \
                    (len(label)*(3/4)), (len(label)-1)])
    else:
        plt.xticks(list(range(0, len(label))))

    plt.savefig(out_file)
    plt.close()

    return True


##################################################
# Error Checking Function
##################################################

def check_errors():
    check_platform()
    check_prerequisites()
    

def check_platform():
    # Checks whether we're on Linux

    if (sys.platform == 'linux' or sys.platform == 'linux2'):
        pass
    else:
        print("[!] Only Linux platform is supported")
        sys.exit(1) 


def check_prerequisites():
    # Checks whether input log file is valid & awk exists

    returncode = run_cmd_exit(['which','awk'])

    if (returncode == 1):
        print("[!] Warning /usr/bin/awk is missing. Quitting")
        sys.exit(1)

    try:
        import matplotlib.pyplot as plt
        from geolite2 import geolite2
    except (ModuleNotFoundError):
        print("[!] Warning required modules not found")
        print("[*] Please install matplotlib, geolite2")
        print("[+] pip3 install --user python-geoip python-geoip-geolite2 matplotlib")
        sys.exit(1)

    

def check_files(files=[]):
    # Iterates over file_list, to verify they exist
    # Returns: Boolean indicating whether all paths are valid files

    if (files != []):
        for f in files:
            if (os.path.isfile(f)):
                pass
            else:
                #print("File %s doesn't exist." % f)
                return False 
        return True


##################################################
# Utility Functions
##################################################

def run_cmd(cmd=[], verbose=False):
    # Executes bash commands on local Linux system

    if (cmd != []):
        process = subprocess.Popen(cmd, shell=True, \
                                   stdout=subprocess.PIPE, \
                                   stderr=subprocess.PIPE)

        stdout,stderr = process.communicate()
        
        stdout = stdout.decode('ascii').strip()
        stderr = stderr.decode('ascii').strip()

        if (verbose == True):
            print(stdout)

        return stdout,stderr


def run_cmd_exit(cmd=[]):
    # Executes bash commands & returns exit status

    if (cmd != []):
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, \
               stderr=subprocess.PIPE)

        stdout,stderr = process.communicate()

        return process.returncode


def load_file(filename=''):
    "Opens given file and returns a list with its contents"


    try:
        tmp_data = open(filename, 'r').readlines()
    except (Exception):
        print("[!] Not able to open file: %s" % filename)
        sys.exit(1)

    return tmp_data


def write_file(out_data=[], filename=''):
    # Writes the specified data to input file
    # Returns Boolean indicating success / failure

    if (out_data != [] and filename != ''):
        try:
            f = open(filename, 'w')

            for i in out_data:
                if (type(i) == tuple):
                    tmp_str = '%s' % i[0]
                    for j in i[1:]:
                        tmp_str = tmp_str + ',%s' % (j)

                    f.writelines('%s\n' % tmp_str)
                else:
                    f.writelines('%s\n' % str(i))
        
            f.close()
        except (BaseException):
            return False

        return True
    else:
        return False


##################################################
#           Commandline Operations
##################################################

def print_intro():
    global version
    print("Fail2Ban Log Analysis - %s" % version)

def print_help():
    print("Usage: %s fail2ban.log" % sys.argv[0])

def check_args():

    if (len(sys.argv) < 2 or len(sys.argv) > 2):
        print_help()
        sys.exit(1)

    input_file = [sys.argv[1]]

    if (check_files(input_file) == False):
        print("[!] Warning file %s not found. Quitting"  % input_file[0]) 
        sys.exit(1)



##################################################
#               Main Function
##################################################

def main():
    global tmp_outfile, save_file, out_data, record

    print_intro()

    check_args()

    check_errors()

    format_fail2ban_log(sys.argv[1], tmp_outfile)

    process_data()

    ## Debugging purposes
    #print_data()

    if (write_file(record, save_file) == False):
        print('[-] Failed trying to write data')

    data = read_file_format_data(save_file)
    plot_bar(data, 'ssh-attacks-by-country.png')
    plot_time_analysis(data, 'ssh-attacks-time.png')

if __name__ == "__main__":
    main()
