import csv
import sys
import pandas as pd
import pyasn
import hashlib
import uuid

output_dir = 'own_scans'

# Initialize a dictionary to store the parsed data for multiple servers
servers = {}
seen_servers = set()
csv.field_size_limit(sys.maxsize)
def parse_ext(cat, ext):
    for i in ext.split('.'):
        i = i.lstrip('-')
        if i.isdigit():
            cat.add(i)

failed = "______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40|______<40"
def parse_fingerprint(server_name, fingerprint, ip):
    # Ensure the server entry exists in servers
    if fingerprint != failed:
    
        if ip not in servers and server_name not in seen_servers:
            servers[ip] = {
                'server_name': server_name,
                'version': set(),
                'ciphers': set(),
                'ext': set(),
                'enc_ext': set(),
                'cert_ext': set(),
                'alerts': set(),
                'fingerprint': set()
            }
            seen_servers.add(server_name)
            parts = fingerprint.split('|')
            hash_object = hashlib.sha256()
            fp = fingerprint
            hash_object.update(fp.encode())
            hash_fp = hash_object.hexdigest()
            servers[ip]['fingerprint'].add(hash_fp)
            for part in parts:
                fields = part.split('_')
                if len(fields) >= 3:
                    if fields[0]:
                        servers[ip]['version'].add(fields[0])
                    if fields[1]:
                        servers[ip]['ciphers'].add(int(fields[1], 16)) #hex to number

                    if fields[2]:
                        for i in fields[2].split('.'):
                            i = i.lstrip('-')
                            if i.isdigit():
                                servers[ip]['ext'].add(i)  
                    if fields[3]:
                        parse_ext(servers[ip]['enc_ext'], fields[3])  
                    if fields[4]:
                        parse_ext(servers[ip]['cert_ext'], fields[4])  

                    # Alerts
                    if '<' in part:
                        alerts = part.split('<')[-1]
                        servers[ip]['alerts'].add(alerts.replace('_', ' '))

# Read from CSV and process each line
row_count = 0
chunk = 10000
with open('../tls-scanner-output_final/fingerprints.csv', mode='r') as file:
    csv_reader = csv.DictReader(file)
    for row in csv_reader:
        parse_fingerprint(row['server_name'], row['fingerprint'], row['ip'])

# Example usage: print the servers dictionary after processing the CSV
#print(servers)

def write_servers_to_csv(servers, filename):
    # Define the header for the CSV file
    fieldnames = ['ip','server_name', 'version', 'ciphers', 'ext', 'enc_ext', 'cert_ext', 'alerts', 'fingerprint']

    # Create and write to the CSV file
    with open(filename, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        
        # Loop through each server and write its data
        for ip, data in servers.items():
            row = {'ip': ip, 'server_name': data['server_name']}
            # Process each category, joining set entries into a single string
            for key in fieldnames[2:]:  # Skip 'server_name' as it's already handled
                #row[key] = '_'.join(data[key])  # Join set items with comma to make them a string
                row[str(key)] = '_'.join(str(item) for item in data[str(key)]) # use this if you have made hex int, use the one above for original cipher data
            writer.writerow(row)

# Example: Assuming 'servers' is your dictionary containing all server data
write_servers_to_csv(servers, f'{output_dir}/tmp_fps.csv')
df = pd.read_csv(f'{output_dir}/tmp_fps.csv')

# Add the new columns
df['input_list'] = 'urlhause_cf'  # Assign the string 'tranco' to the entire column
df['label'] = 1  # Assign the integer 0 to the entire column

# Save the updated DataFrame to a new CSV file
df.to_csv(f'{output_dir}/labelled_fp.csv', index=False)

def build_as_lookup(dat_file):
    return pyasn.pyasn(dat_file)

# Function to determine the AS number for a given IP address
def find_as_number(ip, as_lookup):
    as_number = as_lookup.lookup(ip)[0]
    return as_number

# Function to read the CSV file, determine the AS numbers, and update the CSV
def update_csv_with_as(csv_file, as_lookup, output_file):
    with open(csv_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        # Read the header and add the AS column
        header = next(reader)
        header.append('AS')
        writer.writerow(header)

        # Process each row and update with the AS number
        for row in reader:
            ip = row[1]
            as_number = find_as_number(ip, as_lookup)
            row.append(as_number)
            writer.writerow(row)

# Define file paths

random_uuid = uuid.uuid4()
tm_output_file = filename = str(random_uuid) + ".csv"
dat_file = 'pyasn.2022-02-07.2301.dat'
csv_file = f'{output_dir}/labelled_fp.csv'
output_file = f'{output_dir}/{tm_output_file}'

# Build the AS lookup object and update the CSV
as_lookup = build_as_lookup(dat_file)
update_csv_with_as(csv_file, as_lookup, output_file)
print(f"Final file is: {output_dir}/{tm_output_file}")
