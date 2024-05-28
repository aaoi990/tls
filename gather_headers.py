import pandas as pd
import aiohttp
import asyncio
import time
import os

async def get_head_headers(session, url):
    try:
        async with session.head(url, timeout=10) as response:
            headers = dict(response.headers)
            print(f"URL {url}, response headers: {headers}")
            return str(headers)
    except Exception as e:
        return f"Exception: {e}"

async def process_chunk(session, chunk):
    tasks = []
    for index, row in chunk.iterrows():
        server_name = row['server_name']
        ip_address = row['ip']

        if pd.notna(server_name):
            url = f"https://{server_name}"
        else:
            url = f"https://{ip_address}"

        task = asyncio.create_task(get_head_headers(session, url))
        tasks.append((index, task))

    for index, task in tasks:
        chunk.loc[index, 'http_headers'] = await task

    return chunk

# Function to process the CSV file
async def process_file(input_file, output_file, chunk_size, start_index, write_batch_size):
    # Check if the output file exists
    if os.path.exists(output_file):
        mode = 'a'
        header = False
    else:
        mode = 'w'
        header = True

    accumulated_rows = []
    with open(output_file, mode) as f_out:
        writer = None
        async with aiohttp.ClientSession() as session:
            for chunk in pd.read_csv(input_file, chunksize=chunk_size, skiprows=range(1, start_index + 1)):
                try:
                    processed_chunk = await process_chunk(session, chunk)
                    accumulated_rows.append(processed_chunk)

                    if len(accumulated_rows) * chunk_size >= write_batch_size:
                        # Concatenate accumulated chunks
                        batch_df = pd.concat(accumulated_rows)
                        # Write the accumulated batch to the output file
                        if writer is None and header:
                            batch_df.to_csv(f_out, index=False)
                            writer = True
                        else:
                            batch_df.to_csv(f_out, index=False, header=False)
                        # Clear the accumulated rows
                        accumulated_rows.clear()

                except KeyboardInterrupt:
                    print("KeyboardInterrupt caught, writing file and exiting...")
                    if accumulated_rows:
                        batch_df = pd.concat(accumulated_rows)
                        batch_df.to_csv(f_out, index=False, header=False)
                    exit()

                except Exception as e:
                    print(f"Exception caught: {e}, writing file...")
                    if accumulated_rows:
                        batch_df = pd.concat(accumulated_rows)
                        batch_df.to_csv(f_out, index=False, header=False)

            if accumulated_rows:
                batch_df = pd.concat(accumulated_rows)
                if writer is None and header:
                    batch_df.to_csv(f_out, index=False)
                else:
                    batch_df.to_csv(f_out, index=False, header=False)

    print("Processing complete. Output saved to", output_file)

def main():
    chunk_size = 100  # Adjust this based on your memory constraints
    input_file = '13335_tmp_as.csv'
    output_file = '13335_file_with_headers.csv'
    write_batch_size = 10000  # Write to the output file in batches of 10000 rows

    # Check if the output file exists
    if os.path.exists(output_file):
        # If it does, get the last index processed
        start_index = pd.read_csv(output_file).index[-1] + 1
    else:
        # If it doesn't, start from the beginning
        start_index = 0

    asyncio.run(process_file(input_file, output_file, chunk_size, start_index, write_batch_size))

if __name__ == "__main__":
    main()
