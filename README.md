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
  - **Setup**:
    - Setup and run MoreFixes
    - When finished, deactivate venv
    - Create a new venv (with a different name from the MoreFixes venv!), such as venvCWEPredictor
    - Activate venvCWEPredictor
    - Install necessary packages using **pip install -r requirementsCWEPredictor.txt**
    - Configure the flags to your preference in the **cwe_predictor.py** script
    - Run the CWE Prediction system using **python3 Code/cwe_predictor.py**
- **Required packages**
  - **requirements.txt** has been slightly adapted to ensure the requirements for MoreFixes are installed
  - **requirementsCWEPredictor.txt** is added to ensure all requirements for the CWE Prediction System are installed
    - _Warning: if you do not have a GPU with CUDA support available on your system, or your system does not use a Linux distribution such as Ubuntu, please install another version of PyTorch via https://pytorch.org/._

