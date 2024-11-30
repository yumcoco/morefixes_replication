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


# Create directories for results
RESULTS_DIR = Path("./results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

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


def fetch_summary(engine):
    """Fetch all summary statistics for data with score >= 65."""
    queries = {
        "github_projects": "SELECT COUNT(DISTINCT repo_url) AS count FROM fixes WHERE score >= 65;",
        "unique_cves": "SELECT COUNT(DISTINCT cve_id) AS count FROM cve WHERE cve_id IN (SELECT cve_id FROM fixes WHERE score >= 65);",
        "unique_cwes": "SELECT COUNT(DISTINCT cwe_id) AS count FROM cwe_classification WHERE cve_id IN (SELECT cve_id FROM fixes WHERE score >= 65);",
        "cwe_types": """
            SELECT COUNT(DISTINCT cwe_id) AS count 
            FROM cwe_classification
            WHERE cve_id IN (SELECT cve_id FROM fixes WHERE score >= 65);
        """,
        "unique_commits": "SELECT COUNT(DISTINCT hash) AS count FROM fixes WHERE score >= 65;",
        "total_fixes": "SELECT COUNT(*) AS count FROM fixes WHERE score >= 65;",
        "programming_languages": """
            SELECT COUNT(DISTINCT programming_language) AS count
            FROM file_change
            WHERE hash IN (SELECT hash FROM fixes WHERE score >= 65);
        """
    }
    
    results = {}
    with engine.connect() as conn:
        for key, query in queries.items():
            result = pd.read_sql_query(query, conn)
            print(f"{key}: {result.iloc[0, 0]}")
            results[key] = result.iloc[0, 0]
    
    # Combine all results into a single DataFrame
    summary_data = {
        "Statistic": [
            "GitHub Projects",
            "Unique CVEs",
            "Unique CWEs",
            "CWE Types",
            "Unique Commits",
            "Total Fixes",
            "Programming Languages"
        ],
        "Count": [
            results["github_projects"],
            results["unique_cves"],
            results["unique_cwes"],
            results["cwe_types"],
            results["unique_commits"],
            results["total_fixes"],
            results["programming_languages"]
        ]
    }
    
    summary_df = pd.DataFrame(summary_data)
    return summary_df

# Save data function
def save_to_csv(dataframe, filename):
    """Save as a CSV file"""
    filepath = RESULTS_DIR / f"{filename}.csv"
    summary_df.to_csv(filepath, index=False)
    print(f"Saved to {filepath}")


# main entrance
if __name__ == "__main__":
    engine = create_connection()
    
    if engine:
        # Fetch summary data
        summary_df = fetch_summary(engine)
        # Save summary data to CSV
        save_to_csv(summary_df, "basic_info")

        # Print summary for verification
        print("\nSummary Statistics:")
        print(summary_df)
        print("All results saved to the 'figures' directory.")
