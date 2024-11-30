import pandas as pd
import numpy as np
from sqlalchemy import create_engine
from datetime import datetime
from pathlib import Path
import os

# Set the file paths for saving results
DATA_PATH = Path.cwd() / 'Data'
FIGURE_PATH = Path.cwd() / 'Figures'
RESULT_PATH = Path.cwd() / 'Results'

# Create directories if they do not exist
Path(DATA_PATH).mkdir(parents=True, exist_ok=True)
Path(FIGURE_PATH).mkdir(parents=True, exist_ok=True)
Path(RESULT_PATH).mkdir(parents=True, exist_ok=True)

# connect the database
DB_CONFIG = {
    "user": os.getenv("POSTGRES_USER", "postgrescvedumper"),
    "password": os.getenv("POSTGRES_PASSWORD", "a42a18537d74c3b7e584c769152c3d"),
    "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
    "port": os.getenv("POSTGRES_PORT", 5433),
    "database": os.getenv("POSTGRES_DBNAME", "postgrescvedumper")
}

def create_connection():
    try:
        engine = create_engine(
            f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        print("success to connect the database...")
        return engine
    except Exception as e:
        print(f"fail to connect the database: {e}")
        return None
        
# Clean the time field, converting it to a standard date format
def clean_time_field(df, time_column):
    """
    Clean the time field, converting it to a standard date format.
    Invalid dates are converted to NaT (Not a Time).
    """
    df[time_column] = pd.to_datetime(df[time_column], errors='coerce')  # 'coerce' will convert invalid dates to NaT
    df[time_column].fillna(pd.to_datetime('today'), inplace=True)  # Fill NaT with the current date
    return df

# Function to fetch data in chunks to avoid loading too much data at once
def fetch_data_in_chunks(conn, query, chunk_size=1000):
    """
    Fetch data in chunks to avoid overloading memory with too much data.
    """
    offset = 0
    while True:
        paginated_query = f"{query} LIMIT {chunk_size} OFFSET {offset}"
        chunk = pd.read_sql_query(paginated_query, conn)
        if chunk.empty:
            break
        yield chunk
        offset += chunk_size

# Main data preprocessing function
def preprocess_data():
    # Create database connection
    engine = create_connection()
    
    if engine:
        # Query to fetch data
        print("Fetching data from the database...")
        query = """
            SELECT fx.cve_id, f.filename, f.num_lines_added, f.num_lines_deleted, 
                   f.code_before, f.code_after, c.committer_date, cc.cwe_id
            FROM file_change f
            JOIN commits c ON f.hash = c.hash
            JOIN fixes fx ON c.hash = fx.hash
            JOIN cve cv ON fx.cve_id = cv.cve_id
            JOIN cwe_classification cc ON cv.cve_id = cc.cve_id
        """
        # Fetch data in chunks
        print("Processing the data in chunks...")
        data_chunks = fetch_data_in_chunks(engine, query)
        
        # Concatenate all chunks into one DataFrame
        df = pd.concat(data_chunks, ignore_index=True)
        print(f"Fetched {len(df)} rows of data.")
        
        # Clean the time field
        df = clean_time_field(df, 'committer_date')
        
        # Group data by year (extract year from committer_date)
        df['year'] = df['committer_date'].dt.year
        yearly_distribution = df.groupby('year').size().reset_index(name='fixes')
        
        # Print and save the results
        print("Yearly distribution:")
        print(yearly_distribution)
        yearly_distribution.to_csv(RESULT_PATH / 'yearly_distribution.csv', index=False)
        print("Yearly distribution data saved.")
        
        # Further process and save the cleaned data
        df.to_csv(RESULT_PATH / 'processed_data.csv', index=False)
        print("Processed data saved to 'processed_data.csv'.")
        
        # Close the database connection
        engine.dispose()

# Run the preprocessing function if the script is executed directly
if __name__ == "__main__":
    preprocess_data()
