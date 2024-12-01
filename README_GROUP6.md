# MoreFixes Replication
@inproceedings{akhoundali2024morefixes,
  title={MoreFixes: A large-scale dataset of CVE fix commits mined through enhanced repository discovery},
  author={Akhoundali, Jafar and Nouri, Sajad Rahim and Rietveld, Kristian and Gadyatskaya, Olga},
  booktitle={Proceedings of the 20th International Conference on Predictive Models and Data Analytics in Software Engineering},
  pages={42--51},
  year={2024}
}

## 01 SSS Assignment 2
- **Authors: Jayme Hebinck, Sha Li, Houhua Ma, Samaneh Jalilian**
- **Main tasks:**
  1. Configure the environment
  2. Dump data
  3. Reproduce research
  4. Missing CWE Prediction System
- **Reproduction script directory**
  - **Path: ./Code/Replication**
    - Data preprocessing: **data_preprocess.py**
    - Query morefixes basic metrics：**morefixes_basicinfo.py**
    - Distribution of CVEs and fixed CVEs yearly: **morefixes_yearlycve.py**
    - Distribution of CWE types : **morefixes_cwe_distribution.py**
    -  Top repositories with most CVEs: **morefixes_top_repositories.py**
    - Distribution of fixes in different programming languages:**morefixes_language.py**
  - **Results Path:  ./results_repo**
- **CWE Prediction System**
  - **Path: ./Code**
    - Script: **cwe_predictor.py**
    - Important flags:
      - **HYPERPARAMATERTUNING_FLAG**: Enable this when you want to perform the hyperparameter tuning experiments
        - Warning: Even on a GPU, this can take up to 12 hours (GPU: RTX 4080 SUPER). 
        - False by default
      - **UPDATEDATABASE_FLAG**: Enable this when you want to update the database with the predicted CWE(s)
        - True by default
- **Requirements.txt**
  - Requirements.txt has been slightly adapted to ensure the requirements for the added code are installed

