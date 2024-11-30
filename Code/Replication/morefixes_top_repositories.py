import os
import pandas as pd
import matplotlib.pyplot as plt
from sqlalchemy import create_engine
from pathlib import Path
import seaborn as sns
import ast

# Database configuration
DB_CONFIG = {
    "user": os.getenv("POSTGRES_USER", "postgrescvedumper"),
    "password": os.getenv("POSTGRES_PASSWORD", "a42a18537d74c3b7e584c769152c3d"),
    "host": os.getenv("POSTGRES_HOST", "127.0.0.1"),
    "port": os.getenv("POSTGRES_PORT", 5433),
    "database": os.getenv("POSTGRES_DBNAME", "postgrescvedumper")
}

# Results directories
RESULTS_DIR = Path("./results")
FIGURES_DIR = Path("./figures")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

def create_connection():
    """Create connection to the PostgreSQL database."""
    try:
        engine = create_engine(
            f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"
        )
        print("Connected to the database successfully...")
        return engine
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def fetch_top_repositories(engine, top_n=10):
    """
    Fetch top N repositories with the most CVEs and their CVSSv3 scores.
    """
    query = f"""
    WITH repo_cve_scores AS (
        SELECT
            fixes.repo_url AS repository,
            fixes.cve_id,
            CAST(cve.cvss3_base_score AS FLOAT) AS cvss_score
        FROM fixes
        JOIN cve ON fixes.cve_id = cve.cve_id
        WHERE fixes.score >= 65 AND cve.cvss3_base_score IS NOT NULL
    ),
    repo_cve_counts AS (
        SELECT
            repository,
            COUNT(DISTINCT cve_id) AS cve_count,
            ARRAY_AGG(cvss_score) AS cvss_scores
        FROM repo_cve_scores
        GROUP BY repository
    )
    SELECT
        repository,
        cve_count,
        cvss_scores
    FROM repo_cve_counts
    ORDER BY cve_count DESC
    LIMIT {top_n};
    """
    with engine.connect() as conn:
        df = pd.read_sql_query(query, conn)
    return df


def plot_top_repositories_boxplot(df):
    """
    Plot the CVSSv3 score distribution as boxplots for the top repositories,
    with the order reversed (highest CVE count at the bottom).
    """
    # Sort data by CVE count in descending order
    df = df.sort_values(by="cve_count", ascending=False)

    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Prepare data for boxplots
    data = []
    labels = []
    for _, row in df.iterrows():
        valid_scores = [score for score in row['cvss_scores'] if pd.notnull(score)]  # Exclude null scores
        if valid_scores:
            data.append(valid_scores)
            repo_name = row['repository'].split('/')[-1]
            labels.append(f"{repo_name}\n{int(row['cve_count']):,} CVEs")
    
    # Reverse the data and labels for bottom-up order
    data = data[::-1]
    labels = labels[::-1]

    # Check for empty or single-value groups
    for i, scores in enumerate(data):
        if len(set(scores)) == 1:
            print(f"Warning: Repository {labels[i]} has only a single score: {scores}")
    
    # Create boxplots
    bplot = ax.boxplot(
        data,
        vert=False,
        patch_artist=True,
        showmeans=False,
        showfliers=False,  # Exclude outliers
        widths=0.6
    )
    
    # Customize colors
    colors = sns.color_palette("pastel", len(data))
    for patch, color in zip(bplot['boxes'], colors):
        patch.set_facecolor(color)
    
    # Add single-value markers
    for i, scores in enumerate(data):
        if len(set(scores)) == 1:  # If all values are the same
            ax.scatter(scores[0], i + 1, color="red", label="Single Value" if i == 0 else "")
    
    # Set axis labels and grid
    ax.set_yticks(range(1, len(labels) + 1))
    ax.set_yticklabels(labels)
    ax.set_xticks(range(1, 11))  # X-axis from 1 to 10
    ax.set_xlim([1, 10])  # X-axis range
    ax.set_xlabel("CVSSv3 Score")
    ax.set_title("Top 10 Repositories by CVEs and CVSSv3 Scores")
    ax.grid(axis='x', linestyle='--', alpha=0.7)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "top_repositories_boxplot_reversed.png")
    plt.show()



# Save results to CSV
def save_to_csv(df, filename):
    """Save the data to a CSV file."""
    filepath = RESULTS_DIR / f"{filename}.csv"
    df.to_csv(filepath, index=False)
    print(f"Data saved to {filepath}")

# Main function
if __name__ == "__main__":
    engine = create_connection()
    if engine:
        # Fetch top repositories with CVE counts and CVSSv3 scores
        top_repositories_df = fetch_top_repositories(engine)
        
        # Save results to CSV
        save_to_csv(top_repositories_df, "top_repositories_with_scores")
        
        # Plot the boxplot distribution
        plot_top_repositories_boxplot(top_repositories_df)
        print("All results saved and visualized.")
