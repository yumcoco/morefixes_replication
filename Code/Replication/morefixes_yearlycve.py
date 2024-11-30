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

# Fetch CVE and fixes count per year
def fetch_cve_and_fixes_per_year(engine):
    query = """
    WITH cve_per_year AS (
        SELECT 
            DATE_PART('year', to_timestamp(REPLACE(substring(published_date from 1 for 19), 'Z', '+00:00'), 'YYYY-MM-DD"T"HH24:MI:SS')) AS year, 
            COUNT(*) AS cve_count
        FROM cve
        WHERE published_date IS NOT NULL
        GROUP BY year
    ),
    fixes_per_year AS (
        SELECT 
            DATE_PART('year', committer_date) AS year, 
            COUNT(DISTINCT fixes.cve_id) AS fixed_cve_count
        FROM fixes
        JOIN commits ON fixes.hash = commits.hash
        WHERE committer_date IS NOT NULL
        GROUP BY year
    )
    SELECT 
        cve_per_year.year,
        COALESCE(cve_per_year.cve_count, 0) AS cve_count,
        COALESCE(fixes_per_year.fixed_cve_count, 0) AS fixed_cve_count
    FROM cve_per_year
    FULL OUTER JOIN fixes_per_year ON cve_per_year.year = fixes_per_year.year
    ORDER BY year;
    """
    with engine.connect() as conn:
        df = pd.read_sql_query(query, conn)
    return df

# Plotting the CVE and fixes distribution over the years
def plot_cve_and_fixes_per_year(df):
    plt.figure(figsize=(10, 6))
    # Plot CVE Count
    plt.plot(df['year'], df['cve_count'], label='CVE Count', marker='o', color='red')
    # Plot Fixed CVE Count
    plt.plot(df['year'], df['fixed_cve_count'], label='Fixed CVE Count', marker='x', color='blue')
    
    # Add title and labels
    plt.title('Yearly CVE Count and Fixed CVE Count')
    plt.xlabel('Year')
    plt.ylabel('Count')
    plt.yscale("log")
    
    # Set x-axis range from 1999 to 2024
    plt.xlim([1999, 2024])
    plt.xticks(range(1999, 2025, 5))  # Set ticks every 5 years
    
    # Add legend
    plt.legend()
    
    # Adjust layout and save figure
    plt.tight_layout()
    plt.savefig('figures/yearly_cve_fixes_distribution.png')
    plt.show()

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
        # Fetch yearly CVE and fixed CVE counts
        print("Fetching yearly CVE and fixed CVE counts...")
        cve_and_fixes_df = fetch_cve_and_fixes_per_year(engine)
        print(cve_and_fixes_df)
    
        # Save results to a CSV file
        save_to_csv(cve_and_fixes_df, "cve_yearly_summary")
    
        # Plot the distribution
        print("Generating distribution plot...")
        plot_cve_and_fixes_per_year(cve_and_fixes_df)

        print("All results saved to the 'figures' directory.")
