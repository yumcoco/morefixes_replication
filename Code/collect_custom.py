import json
import pathlib
import psycopg2
import sys
import time

import pandas as pd

import configuration as cf
import database as db
from database import create_session
from collect_projects import convert_runtime, fetch_and_store_commits, populate_fixes_table
from cve_importer import preprocess_jsons, assign_cwes_to_cves
from utils import prune_tables

session = create_session()
conn = session.connection()


# ---------------------------------------------------------------------------------------------------------------------


def import_custom_json(path: str, conn) -> pd.DataFrame:
    """
    Imports a custom CVE JSON file to a sqlite3 database
    """

    try:
        with open(path) as file:
            cve_data = json.load(file)
            df = pd.DataFrame(cve_data)
    except IOError as err:
        raise IOError(err)

    df = preprocess_jsons(df)
    df = df.apply(lambda x: x.astype(str))
    assert df.cve_id.is_unique, 'Primary keys are not unique in cve records!'
    df.to_sql(name="cve", con=conn, if_exists="replace", index=False)
    conn.commit()

    return df


if __name__ == "__main__":
    start_time = time.perf_counter()

    if len(sys.argv) != 2:
        raise ValueError("collect_custom.py requires path to JSON file as an argument.")

    # Retrieve argument for path to JSON file
    path_to_json = sys.argv[1]

    if not pathlib.Path(path_to_json).is_file():
        raise FileNotFoundError(f"File on path {path_to_json} does not exist.")

    # 1. Import, preprocess, and save CVEs to database
    df_cve = import_custom_json(path=path_to_json, conn=conn)

    # 2. Extract CWEs and assign them to CVEs
    assign_cwes_to_cves(df_cve)

    # 3. Save commit-, file-, and method- level data tables to the database
    fetch_and_store_commits(populate_fixes_table())

    # 4. Pruning the database tables
    # if db.table_exists('method_change'):
    #     prune_tables(cf.DATABASE)
    # else:
    #     cf.logger.warning('Data pruning is not possible because there is no information in method_change table')

    cf.logger.info('The database is up-to-date.')
    cf.logger.info('-' * 70)
    end_time = time.perf_counter()
    hours, minutes, seconds = convert_runtime(start_time, end_time)
    cf.logger.info(f'Time elapsed to pull the data {hours:02.0f}:{minutes:02.0f}:{seconds:02.0f} (hh:mm:ss).')
