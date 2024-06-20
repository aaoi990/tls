import pandas as pd
import aiohttp
import asyncio
import os
import uuid

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
        print(f"Processing row {index} with server_name {server_name} and ip_address {ip_address}")

        if pd.notna(server_name):
            url = f"https://{server_name}"
        else:
            url = f"https://{ip_address}"

        task = asyncio.create_task(get_head_headers(session, url))
        tasks.append((index, task))

    for index, task in tasks:
        chunk.loc[index, 'http_headers'] = await task

    return chunk

async def process_file(input_file, output_file, chunk_size, start_index, write_batch_size):
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
            for chunk in pd.read_csv(input_file, chunksize=chunk_size):
                try:
                    processed_chunk = await process_chunk(session, chunk)
                    accumulated_rows.append(processed_chunk)

                    if len(accumulated_rows) * chunk_size >= write_batch_size:
                        batch_df = pd.concat(accumulated_rows)
                        if writer is None and header:
                            batch_df.to_csv(f_out, index=False)
                            writer = True
                        else:
                            batch_df.to_csv(f_out, index=False, header=False)
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

def gather_headers(output_dir, expanded_fp_file):
    random_uuid = uuid.uuid4()
    chunk_size = 100  
    input_file = f"{output_dir}/{expanded_fp_file}"
    output_file = f"{output_dir}/{random_uuid}.csv"
    write_batch_size = 100 
    if os.path.exists(output_file):
        start_index = pd.read_csv(output_file).index[-1] + 1
    else:
        start_index = 0

    asyncio.run(process_file(input_file, output_file, chunk_size, start_index, write_batch_size))
    
    return output_file

