import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sqlalchemy import create_engine
from pathlib import Path
import numpy as np

# connect the database
DB_CONFIG = {
    "user": os.getenv("POSTGRES_USER", "postgrescvedumper"),
    "password": os.getenv("POSTGRES_PASSWORD", "a42a18537d74c3b7e584c769152c3d"),
    "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
    "port": os.getenv("POSTGRES_PORT", 5433),
    "database": os.getenv("POSTGRES_DBNAME", "postgrescvedumper")
}

# Directories for results and figures
RESULTS_DIR = Path("./results")
FIGURES_DIR = Path("./figures")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

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

def fetch_top_cwe_types(engine):
    """
    Fetch top 10 most frequent CWE types with score >= 65 and the CVE count per CWE
    """
    query = """
    WITH cve_per_cwe AS (
        SELECT cc.cwe_id, COUNT(DISTINCT cc.cve_id) AS cve_count
        FROM cwe_classification cc
        JOIN fixes f ON cc.cve_id = f.cve_id
        WHERE f.score >= 65
        GROUP BY cc.cwe_id
    )
    SELECT cwe_id, cve_count
    FROM cve_per_cwe
    ORDER BY cve_count DESC
    LIMIT 10;
    """
    return pd.read_sql_query(query, con=engine)

def fetch_cwe_type_count(engine):
    """
    Fetch the total number of distinct CWE types with score >= 65
    """
    query = """
    SELECT COUNT(DISTINCT cwe_id) AS cwe_type_count
    FROM cwe_classification cc
    JOIN fixes f ON cc.cve_id = f.cve_id
    WHERE f.score >= 65;
    """
    return pd.read_sql_query(query, con=engine)

def plot_top_cwe_types(cwe_df):
    """
    Plot the top 10 most frequent CWE types
    """
    plt.figure(figsize=(12, 8))
    sns.barplot(data=cwe_df, x='cve_count', y='cwe_id', palette=sns.color_palette("Set3", len(cwe_df)))
    plt.title("Top 10 Most Frequent CWE Types (Score >= 65)")
    plt.xlabel("Number of CVEs")
    plt.ylabel("CWE ID")
    plt.tight_layout()
    plt.savefig("figures/top_10_cwe_types.png")
    plt.show()

# Function to save the data to CSV
def save_to_csv(df, filename):
    """Save the data to CSV."""
    filepath = f"results/{filename}.csv"
    df.to_csv(filepath, index=False)
    print(f"Data saved to {filepath}")



# Save data function
def save_to_csv(dataframe, filename):
    """Save as a CSV file"""
    filepath = f"results/{filename}.csv"
    dataframe.to_csv(filepath, index=False)
    print(f"Data saved to{filepath}")


# main entrance
if __name__ == "__main__":
    engine = create_connection()
    
    if engine:
       # Fetch top CWE types with score >= 65
        cwe_data = fetch_top_cwe_types(engine)

        # Fetch total CWE type count
        cwe_type_count = fetch_cwe_type_count(engine)

        # Save results to CSV (top CWE types)
        save_to_csv(cwe_data, "top_10_cwe_types")

        # Add the total CWE type count to the CSV file as a separate row
        total_cwe_row = pd.DataFrame([["Total CWE Types", cwe_type_count['cwe_type_count'][0]]], 
                                     columns=["cwe_id", "cve_count"])
        cwe_with_total = pd.concat([cwe_data, total_cwe_row], ignore_index=True)
        save_to_csv(cwe_with_total, "top_10_cwe_types_with_total")

        # Plot the top CWE types (only the original 10 rows)
        plot_top_cwe_types(cwe_data)

        print("All results saved to the directory.")
