import pandas as pd
import aiohttp
import asyncio
import uuid

async def get_head_headers(session, url):
    try:
        async with session.head(url, timeout=10) as response:
            headers = dict(response.headers)
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

async def process_file(input_file, output_file, chunk_size, write_batch_size):
    accumulated_rows = []
    first_batch = True 
    with open(output_file, 'w') as f_out:
        async with aiohttp.ClientSession() as session:
            for chunk in pd.read_csv(input_file, chunksize=chunk_size):
                try:
                    processed_chunk = await process_chunk(session, chunk)
                    accumulated_rows.append(processed_chunk)                    
                    if len(accumulated_rows) * chunk_size >= write_batch_size:
                        batch_df = pd.concat(accumulated_rows)
                        if first_batch: 
                            batch_df.to_csv(f_out, index=False)
                            first_batch = False  
                        else:
                            batch_df.to_csv(f_out, index=False, header=False)
                        accumulated_rows.clear()

                except Exception as e:
                    print(f"Exception caught: {e}, writing file...")
                    if accumulated_rows:
                        batch_df = pd.concat(accumulated_rows)
                        if first_batch:  
                            batch_df.to_csv(f_out, index=False)
                            first_batch = False
                        else:
                            batch_df.to_csv(f_out, index=False, header=False)

            if accumulated_rows:
                batch_df = pd.concat(accumulated_rows)
                if first_batch:
                    batch_df.to_csv(f_out, index=False)
                else:
                    batch_df.to_csv(f_out, index=False, header=False)

def gather_headers(output_dir, expanded_fp_file):
    random_uuid = uuid.uuid4()
    chunk_size = 100 
    input_file = f"{output_dir}/{expanded_fp_file}"
    output_file = f"{output_dir}/{random_uuid}.csv"
    write_batch_size = 1000 

    asyncio.run(process_file(input_file, output_file, chunk_size, write_batch_size))
    
    return output_file

