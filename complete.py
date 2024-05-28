import argparse
import ast
import csv
from email import header
import hashlib
import re
import sys
import uuid
import os

import mmh3
import pandas as pd
import pyasn

from header_module import gather_headers

servers = {}
seen_servers = set()
csv.field_size_limit(sys.maxsize)

def parse_ext(cat, ext):
    for i in ext.split('.'):
        i = i.lstrip('-')
        if i.isdigit():
            cat.add(i)

def parse_fingerprint(server_name, fingerprint, ip):
    failed = "______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40"
    # Ensure the server entry exists in servers
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

def build_as_lookup(dat_file):
    return pyasn.pyasn(dat_file)

def find_as_number(ip, as_lookup):
    as_number = 0
    try:
        as_number = as_lookup.lookup(ip)[0]
    except:
        print(f"Error looking up AS number for IP: {ip}")
    return as_number

def update_csv_with_as(csv_file, as_lookup, output_file):
    with open(csv_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        header = next(reader)
        header.append('AS')
        writer.writerow(header)

        for row in reader:
            ip = row[0]
            as_number = find_as_number(ip, as_lookup)
            row.append(as_number)
            writer.writerow(row)


def write_servers_to_csv(servers, filename):
    fieldnames = ['server_name', 'ip','version', 'ciphers', 'ext', 'enc_ext', 'cert_ext', 'alerts', 'fingerprint']

    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        
        for ip, data in servers.items():
            row = {'ip': ip[0], 'server_name': data['server_name']}
            for key in fieldnames[2:]:  
                row[str(key)] = '_'.join(str(item) for item in data[str(key)]) 
            writer.writerow(row)


def extract_ssl_failure_reason(exception_message):
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
    print(filtered_headers_string)
    return filtered_headers_string.strip() 

def create_mmh3_hash(header_str):
    return mmh3.hash(header_str, signed=False)

def append_hash_to_fingerprint(row):
    if pd.notna(row['fingerprint']):
        return f"{row['fingerprint']}_{row['filtered_http_headers_hash']}"
    else:
        return str(row['filtered_http_headers_hash'])

def create_headers(extended_fp_file): 
    print(extended_fp_file)
    df = pd.read_csv(extended_fp_file) ##fix
    df['filtered_http_headers'] = df['http_headers'].apply(process_headers)    
    df['filtered_http_headers_hash'] = df['filtered_http_headers'].apply(create_mmh3_hash)   
    basename, _ = os.path.splitext(extended_fp_file) 
    df.to_csv(f"{basename}_final.csv", index=False)
    return f"{basename}_final.csv"


def main(input_list_value, label_value, output_dir, fingerprint_file, create_header_fp):
    with open(fingerprint_file, mode='r') as file:
        csv_reader = csv.DictReader(file)
        for row in csv_reader:
            parse_fingerprint(row['server_name'], row['fingerprint'], row['ip'])

    write_servers_to_csv(servers, f'{output_dir}/tmp_fps.csv')
    df = pd.read_csv(f'{output_dir}/tmp_fps.csv')    
    df['input_list'] = input_list_value 
    df['label'] = label_value  
    df.to_csv(f'{output_dir}/labelled_fp.csv', index=False)
    random_uuid = uuid.uuid4()
    tm_output_file = filename = str(random_uuid) + ".csv"
    dat_file = 'pyasn.2022-02-07.2301.dat'
    csv_file = f'{output_dir}/labelled_fp.csv'
    output_file = f'{output_dir}/{tm_output_file}'

    as_lookup = build_as_lookup(dat_file)
    update_csv_with_as(csv_file, as_lookup, output_file)    
    
    if create_header_fp:
        header_file = gather_headers(output_dir, tm_output_file)
        final_file = create_headers(header_file)        
        print(f"Final file is: {final_file}")
    else:
        print(f"Final file is: {output_dir}/{tm_output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process DataFrame column assignments.")
    parser.add_argument("-i","--input_list_value", type=str, default="cert.pl", help="Value to assign to the 'input_list' column")
    parser.add_argument("-l","--label_value", type=int, default=1, help="Value to assign to the 'label' column")
    parser.add_argument("-o","--output_dir", type=str, default="output_dir = 'own_scans'", help="Output directory for the final CSV file")
    parser.add_argument("-f","--fingerprints_file", type=str, default="fingerprints.csv", help="File containing the fingerprints")
    parser.add_argument("-c","--create_header_fp", action="store_true", help="Launches the header fingerprint creation")
    args = parser.parse_args()

    main(args.input_list_value, args.label_value, args.output_dir, args.fingerprints_file, args.create_header_fp)
