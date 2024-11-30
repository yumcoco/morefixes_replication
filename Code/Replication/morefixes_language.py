import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sqlalchemy import create_engine
from pathlib import Path

# Database configuration
DB_CONFIG = {
    "user": os.getenv("POSTGRES_USER", "postgrescvedumper"),
    "password": os.getenv("POSTGRES_PASSWORD", "a42a18537d74c3b7e584c769152c3d"),
    "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
    "port": os.getenv("POSTGRES_PORT", 5433),
    "database": os.getenv("POSTGRES_DBNAME", "postgrescvedumper")
}

# Result directories
RESULTS_DIR = Path("./results")
FIGURES_DIR = Path("./figures")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

def create_connection():
    """Create a connection to the PostgreSQL database."""
    try:
        engine = create_engine(
            f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        print("Successfully connected to the database...")
        return engine
    except Exception as e:
        print(f"Failed to connect to the database: {e}")
        return None

def fetch_file_changes_by_language_morefixes(engine):
    """
    Fetch the number of file changes grouped by programming language from MoreFixes.
    """
    query = """
    SELECT 
        programming_language, 
        COUNT(*) AS file_changes
    FROM file_change
    WHERE programming_language IS NOT NULL
    GROUP BY programming_language
    ORDER BY file_changes DESC
    LIMIT 20;  -- Only top 20 results
    """
    return pd.read_sql_query(query, con=engine)

def plot_morefixes_file_changes(df):
    """
    Plot the distribution of file changes for the top 20 programming languages in MoreFixes, from low to high.
    """
    # Sort the data by file changes in ascending order
    df = df.sort_values(by="file_changes", ascending=True)

    plt.figure(figsize=(10, 8))
    sns.barplot(data=df, x="file_changes", y="programming_language", palette="pastel")
    plt.title("Distribution of File Changes in MoreFixes by Programming Language")
    plt.xlabel("Number of File Changes")
    plt.ylabel("Programming Language")
    plt.tight_layout()
    plt.savefig("figures/morefixes_file_changes_sorted.png")
    plt.show()

def save_to_csv(df, filename):
    """Save the data to a CSV file."""
    filepath = RESULTS_DIR / f"{filename}.csv"
    df.to_csv(filepath, index=False)
    print(f"Data saved to {filepath}")

if __name__ == "__main__":
    engine = create_connection()
    if engine:
        # Fetch MoreFixes data
        morefixes_data = fetch_file_changes_by_language_morefixes(engine)
        
        # Save results to CSV
        save_to_csv(morefixes_data, "morefixes_file_changes")
        
        # Plot the distribution of file changes
        plot_morefixes_file_changes(morefixes_data)
        
        print("Data and visualization for MoreFixes saved successfully.")
