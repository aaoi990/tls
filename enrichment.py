import argparse
import ast
import csv
import hashlib
import os
import re
from datetime import datetime
import uuid

import mmh3
import pandas as pd
import pyasn

from header_module import gather_headers

servers = {}
seen_servers = set()

def parse_ext(cat: set, ext: str):
    """
    Helper function that parses the specific extention format from the ActiveTLS tool.
    Handles the use case when the fingerprint data has a base64 encoded value with another extension
    appended for example: 
        AAoAHQAXAB4AGQAY-16. This ensures the '16' is recoded as an extension.

    Args:
        cat (set): A set to store the parsed extension values in this case enc_ext or cert_ext.
        ext (str): The extension value to be parsed.

    Returns:
        None: This function does not return a value it updates the provided set with the parsed extension
    """
    for i in ext.split('.'):
        i = i.lstrip('-')
        if i.isdigit():
            cat.add(i)

def parse_fingerprint(server_name: str, fingerprint: str, ip: str):
    """
    This extracts the raw fingerprint data from the provided fingeprint.csv file. It breaks down the 
    ActiveTLS stack fingerprint into it's individual componenets. The process maintains a set of tuples
    for each ip:server_name seen to avoid duplication but accounting for the fact that you can have multiple 
    domains on an Ip address. The combines all the TLS features seen across all CH scans into a single 
    dictionary for each ip:server_name tuple.

    Args:
        server_name (str): The name of the server.
        fingerprint (str): The row containg the fingerprint data.
        ip (str): The IP address of the server.

    Returns:
        None: This function does not return a value, it updates the global servers dictionary. 
    """
    failed = "______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40"
    if fingerprint != failed:    
        if (ip, server_name) not in seen_servers:              
            seen_servers.add((ip, server_name))             
            servers[(ip, server_name)] = {
                'ip': ip, 
                'server_name': server_name,
                'version': set(),
                'ciphers': set(),
                'ext': set(),
                'enc_ext': set(),
                'cert_ext': set(),
                'alerts': set(),
                'fingerprint': set()
            }
            parts = fingerprint.split('|')
            hash_object = hashlib.sha256()
            fp = fingerprint
            hash_object.update(fp.encode())
            hash_fp = hash_object.hexdigest()
            servers[(ip, server_name)]['fingerprint'].add(hash_fp)
            for part in parts:
                fields = part.split('_')
                if len(fields) >= 3:
                    if fields[0]:
                        servers[(ip, server_name)]['version'].add(fields[0])
                    if fields[1]:
                        servers[(ip, server_name)]['ciphers'].add(int(fields[1], 16)) #hex to number

                    if fields[2]:
                        for i in fields[2].split('.'):
                            i = i.lstrip('-')
                            if i.isdigit():
                                servers[(ip, server_name)]['ext'].add(i)  
                    if fields[3]:
                        parse_ext(servers[(ip, server_name)]['enc_ext'], fields[3])  
                    if fields[4]:
                        parse_ext(servers[(ip, server_name)]['cert_ext'], fields[4])  

                    if '<' in part:
                        alerts = part.split('<')[-1]
                        servers[(ip, server_name)]['alerts'].add(alerts.replace('_', ' '))

            servers[(ip, server_name)]['version'] = (sorted(servers[(ip, server_name)]['version']))
            servers[(ip, server_name)]['ciphers'] = (sorted(map(str, servers[(ip, server_name)]['ciphers'])))
            servers[(ip, server_name)]['ext'] = (sorted(servers[(ip, server_name)]['ext']))
            servers[(ip, server_name)]['enc_ext'] = (sorted(servers[(ip, server_name)]['enc_ext']))
            servers[(ip, server_name)]['cert_ext'] =(sorted(servers[(ip, server_name)]['cert_ext']))
            servers[(ip, server_name)]['alerts'] =  sorted(servers[(ip, server_name)]['alerts'])
    

def find_as_number(ip: str, as_lookup: pyasn.pyasn):
    """
    Simple function to return the AS number thaat the IP
    address belongs to. 
    
    Args:
        ip (str): A set to store the parsed extension values in this case enc_ext or cert_ext.
        as_lookup (str): The pyasn object to be used for the ip -> as lookup

    Returns:
        as_number (int): The AS number, or if none is found in the lookup, 0
    """
    as_number = 0
    try:
        as_number = as_lookup.lookup(ip)[0]
    except:
        print(f"Error looking up AS number for IP: {ip}")
    return as_number


def update_dataframe_with_as(dataframe: pd.DataFrame, as_lookup: pyasn.pyasn):
    """
    Updates the dataframe per row with the correct AS based on the ip address within
    the row.  
    
    Args:
        dataframe (pd.DataFrame): The intital pandas dataframe with the fingerprint breakdown.
        as_lookup (str): The pyasn object to be used for the ip -> as lookup

    Returns:
        dataframe (pd.DataFrame): The new dataframe with the updated AS column
    """
    dataframe['AS'] = dataframe['ip'].apply(lambda ip: find_as_number(ip, as_lookup))
    return dataframe


def write_servers_to_dataframe(servers: dict):
    """
    Creates a new pandas dataframe with the required column headings which consist of the
    break down of the TLS features per server.
    
    Args:
        server (dict): The servers dictionary that was generated in the parse_fingerprint function 

    Returns:
        dataframe (pd.DataFrame): New data frame containing the TLS fingerprint breakdown per server.
    """
    fieldnames = ['ip', 'server_name', 'version', 'ciphers', 'ext', 'enc_ext', 'cert_ext', 'alerts', 'fingerprint']

    rows = []
    for _,data in servers.items():
        row = {'ip': data['ip'], 'server_name': data['server_name']}
        for key in fieldnames[2:]:
            row[str(key)] = '_'.join(str(item) for item in data[str(key)])
        rows.append(row)
    
    df = pd.DataFrame(rows, columns=fieldnames)
    return df


def extract_ssl_failure_reason(exception_message: str):
    """
    Parses the expection string to ensure specififc error messages are saved as port of the fingerprint.
    In this case, we want to ensure that ssl messages that relate to certificate errors
    are captured as they could be indicators of malware. Common deployments will often have similar
    ssl certificate issues. Some example of ssl errors: Hostname mismatch, self-signed certificate, 
    certificate has expired.
    
    Args:
        exception_message (str): Exception message to be parsed 

    Returns:
        str: The matched exception string, or an empty string.
    """

    pattern = r"certificate verify failed: (.*?)(?=,|\(_ssl\.c:1133\))"
    match = re.search(pattern, exception_message)
    if match:
        return match.group(1)
    else:
        return ""
    
def process_headers(headers):    
    headers_to_keep_values = ['Server']   
    filtered_headers_string = ""
    try:
        headers_dict = ast.literal_eval(headers)
        for key in headers_dict:
            if key in headers_to_keep_values:
                filtered_headers_string += f"{key}:{headers_dict[key]} "
            else:
                filtered_headers_string += f"{key} "
    except Exception as e:
        print(f"Error processing headers: {e}")
        filtered_headers_string = extract_ssl_failure_reason(headers)
    return filtered_headers_string.strip() 

def create_mmh3_hash(header_str: str):
    """
    Creates a signed mmh3 hash of the filtered header string - so the header keys (and
    specifically included values, so in this case the 'server' header value only) in
    order.  
    
    Args:
        header_str (str): The filtered header string to be hashed

    Returns:
        header_str (int): The hash of the header string in mmh3 format (example 4118047921)
    """
    return mmh3.hash(header_str, signed=False)


def create_headers(extended_fp_file, input_list_value): 
    df = pd.read_csv(extended_fp_file) 
    df['filtered_http_headers'] = df['http_headers'].apply(process_headers)    
    df['filtered_http_headers_hash'] = df['filtered_http_headers'].apply(create_mmh3_hash)   

    directory = os.path.dirname(extended_fp_file) 
    now = datetime.now()
    date_string = now.strftime("%d_%m_%y")
    file_name = f"{input_list_value}_{date_string}"
    df.to_csv(f"{directory}/{file_name}_final.csv", index=False)
    return f"{directory}/{file_name}_final.csv"


def main(input_list_value, label_value, output_dir, fingerprint_file, create_header_fp):
    """ 
    Launches the fingerprint extractions and creation process. In this instance it's preferable 
    to use a csv.DictReader to avoid having to read the entire csv file into memory as the
    fingerprint files can be very large.
    
    Args:
        input_list_value (str): A value to be added to the 'input_list' column in the output DataFrame.
        label_value (str): A value to be added to the 'label' column in the output DataFrame.
        output_dir (str): The directory where the output CSV files will be saved.
        fingerprint_file (str): The path to the CSV file containing fingerprint data to be processed.
        create_header_fp (bool): A flag indicating whether to create a header fingerprint file. If True,
                                 additional processing to create and update a headers fingerprint file is performed.

    Returns:
        None: This function does not return a value but writes the processed data to CSV files in 
        the specified output directory.
    """

    with open(fingerprint_file, mode='r') as file:
        count = 0
        csv_reader = csv.DictReader(file)
        for row in csv_reader:            
            row_list = list(row.values())
            parse_fingerprint(row_list[0], row['fingerprint'], row_list[2])
            count += 1
            if count == 30:
                break

    df = write_servers_to_dataframe(servers)  
    df['input_list'] = input_list_value 
    df['label'] = label_value  

    random_uuid = uuid.uuid4()
    tm_output_file = str(random_uuid) + ".csv"
    dat_file = 'pyasn.2022-02-07.2301.dat'
    output_file = f'{output_dir}/{tm_output_file}'

    as_lookup = pyasn.pyasn(dat_file) 
    df = update_dataframe_with_as(df, as_lookup)
    df.to_csv(output_file, index=False)
    
    if create_header_fp:
        header_file = gather_headers(output_dir, tm_output_file)        
        final_file = create_headers(header_file, input_list_value)         
        df = pd.read_csv(final_file)
        df['final_fp'] = df['fingerprint'].astype(str) + df['filtered_http_headers_hash'].astype(str)
        df.to_csv(final_file, index=False)       
        print(f"Final file is: {final_file}")

        os.remove(output_file)
        os.remove(header_file)
    else:
        print(f"Final file is: {output_dir}/{tm_output_file}")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process DataFrame column assignments.")
    parser.add_argument("-i","--input_list_value", type=str, default="GOOD", help="Value to assign to the 'input_list' column")
    parser.add_argument("-l","--label_value", type=int, default=0, help="Value to assign to the 'label' column")
    parser.add_argument("-o","--output_dir", type=str, default="output_dir = '/tmp'", help="Output directory for the final CSV file")
    parser.add_argument("-f","--fingerprints_file", type=str, default="fingerprints.csv", help="File containing the fingerprints")
    parser.add_argument("-c","--create_header_fp", action="store_true", help="Launches the header fingerprint creation")
    args = parser.parse_args()

    main(args.input_list_value, args.label_value, args.output_dir, args.fingerprints_file, args.create_header_fp)
