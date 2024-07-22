import pandas as pd
import aiohttp
import asyncio
import uuid

async def get_head_headers(session, url):
    """
    Asynchronously sends a HEAD request to a given URL and returns the headers.

    Args:
        session (aiohttp.ClientSession): The session object to use for the request.
        url (str): The URL to send the request to.

    Returns:
        str: The headers of the response.
    """
    try:
        async with session.head(url, timeout=10) as response:
            headers = dict(response.headers)
            return str(headers)
    except Exception as e:
        return f"Exception: {e}"

async def process_chunk(session, chunk):
    """
    Asynchronously processes a chunk of a fingerprint file and calls the get_head_headers
    function for each row in the chunk. The headers are then stored in the 'http_headers'
    column of the chunk.

    Args:
        session (aiohttp.ClientSession): The session object to use for the request.
        chunk (pandas.DataFrame): The chunk of the fingerprint file to process.

    Returns:
        pandas.DataFrame: The processed chunk with the 'http_headers' column added.
    """
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
    """
    Asynchronously processes a fingerprint file and calls the process_chunk
    function for each chunk in the csv. The processed chunks are then written
    to an output file.  

    Args:
        input_file (str): The name of the file to be processed.
        output_file (str): The name of the output file.
        chunk_size (int): The number of rows to read at a time.
        write_batch_size (int): The number of rows to write at a time.

    Returns:
        None
    """
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
    """
    Asynchronously processes a fingeprrint file and calls the process_file 
    function for each row in the csv.

    Args:
        output_dir (str): The directory where the input file is located and where 
        the output CSV file will be saved.
        expanded_fp_file (str): The name of the file to be processed.

    Returns:
        str: The path to the generated output CSV file containing the processed headers.
    """
    chunk_size = 100 
    input_file = f"{output_dir}/{expanded_fp_file}"
    output_file = f"{output_dir}/{uuid.uuid4()}.csv"
    write_batch_size = 1000 
    asyncio.run(process_file(input_file, output_file, chunk_size, write_batch_size))
    
    return output_file

