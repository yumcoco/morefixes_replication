# By: Samaneh Jalilian s3787230, Sha Li s4294092, Jayme Hebinck s2736136, Houhua Ma s4247477
# SSS Assignment 2 - Group 6
# 
# This Python script aims to predict CWEs for CVEs with missing CWE information. 
# The addition of these predictions is to make the references of the database more complete.

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MultiLabelBinarizer
from sqlalchemy import create_engine, text
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, AdamW
from sklearn.metrics import accuracy_score, f1_score, hamming_loss, precision_score, recall_score
from tqdm import tqdm
import torch
from torch.utils.data import DataLoader, TensorDataset
import ast
import itertools

# Two important flags that influence what the CWE Predictor does!

# Enable this when you want to perform the hyperparameter tuning experiments
# Warning: Even on a GPU, this can take up to 12 hours (GPU: RTX 4080 SUPER)
# FALSE BY DEFAULT
HYPERPARAMATERTUNING_FLAG = False 

# Enable this when you want to update the database with the predicted CWE(s)
# TRUE BY DEFAULT
UPDATEDATABASE_FLAG = True

def create_connection(db_name, db_user, db_password, db_host, db_port):
    # Create a connection to the Postgre database using the provided information
    print()
    print("|| Creating connection with PostgreSQL Database ||")
    try:
        engine = create_engine(f'postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}')
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    print("Connection Successful!")
    return engine

def data_processing(engine):
    # Get all CVEs with respective CWEs from the cwe_classification table
    query = "SELECT cve_id, cwe_id FROM cwe_classification"
    df = pd.read_sql(query, engine) # Convert it into a Pandas data frame

    # Every line contains one CVE with one CWE, so there can be multiple lines of the same CVE with different CWEs
    # Change this, so that all CWEs for one CVE are on one line
    dfY = df.groupby('cve_id')['cwe_id'].apply(lambda x: ','.join(x)).reset_index()

    # Get all CVEs with their description from the cve table
    query = "SELECT cve_id, description FROM cve"
    dfX = pd.read_sql(query, engine) # Convert it into a Pandas data frame

    # Safely handle possible stringified lists and null entries
    dfX['description'] = dfX['description'].apply(lambda x: ast.literal_eval(x) if isinstance(x, str) else x)

    # Extract the 'value' from the first dictionary if the list exists and is non-empty
    dfX['description'] = dfX['description'].apply(lambda x: x[0]['value'] if isinstance(x, list) and len(x) > 0 and 'value' in x[0] else None)
    dfX = dfX.drop(dfX.columns[0], axis=1)  # Drop the third column (a double CVE column)
    df_combined = pd.concat([dfX, dfY], axis=1) # Concatenate the two separate data frames
    print(df_combined)
    
    # We now have one data frame with the CVEs, corresponding CWE(s) and description of the CVEs
    # Divide this into two separate data frame: one with known CWE(s) and one with unknown CWE(s)
    df_noinfo = df_combined[df_combined['cwe_id'] == 'NVD-CWE-noinfo']  
    df_filtered = df_combined[df_combined['cwe_id'] != 'NVD-CWE-noinfo']  

    return df_noinfo, df_filtered

def tokenize_and_prepare_dataloader(X, Y, tokenizer, batch_size=8):
    # Tokenize the data so that it can be used to train the model
    inputs = tokenizer(X.tolist(), padding=True, truncation=True, return_tensors="pt", max_length=512)
    input_ids = inputs['input_ids']
    attention_mask = inputs['attention_mask']

    # Prepare the dataloader which contains the batches of tokenized data
    dataset = TensorDataset(input_ids, attention_mask, torch.tensor(Y, dtype=torch.float32))
    dataloader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
    
    return dataloader

def train(model, dataloader, optimizer, criterion, device):
    # Train the model using the model.train() functionality
    model.train()
    total_loss = 0
    for batch in tqdm(dataloader):
        # For every batch, gather the input ids, attention mask and labels
        input_ids, attention_mask, labels = [x.to(device) for x in batch]
        optimizer.zero_grad()
        
        # Retrieve the output of the training step
        outputs = model(input_ids, attention_mask=attention_mask)

        # Calculate the loss and perform optimization step
        loss = criterion(outputs.logits, labels)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()

    # Retun the loss
    return total_loss / len(dataloader)

def evaluate(model, dataloader, device):
    # Evaluate the model using the model.eval() functionality
    model.eval()
    predictions, true_labels = [], [] # Initialize empty lists for predictions and true labels
    with torch.no_grad():
        for batch in dataloader:
            # For every batch, gather the input ids, attention mask and labels
            input_ids, attention_mask, labels = [x.to(device) for x in batch]

            # Retrieve the output of the evaluation
            outputs = model(input_ids, attention_mask=attention_mask)

            # Transform the output to logits and convert both the logits and labels to NumPy data frames
            logits = outputs.logits.detach().cpu().numpy()
            labels = labels.cpu().numpy()
            
            # Extend the predictions and true labels lists with the new output
            predictions.extend(np.round(torch.sigmoid(torch.tensor(logits)).numpy()))
            true_labels.extend(labels)
    
    # Return the predictions and true labels, these are later on compared
    return predictions, true_labels

def update_cwe_labels(engine, df_updated):
    # Updates the CWEs of their respective CVEs in the cwe_classification table
    print()
    print("|| Updating CWE labels in the database ||")
    
    # Check if connection to the database is still online
    with engine.connect() as conn:
        for index, row in df_updated.iterrows():
            # Go over all the rows of the data frame, assign the CVE and predicted CWE(s) in the rows
            cve_id = row['cve_id']
            predicted_cwe = row['cwe_id']  # Assumes 'cwe_id' contains the new predicted CWE label(s)

            # Send a query with the update information
            update_query = text("""
                UPDATE cwe_classification
                SET cwe_id = :predicted_cwe
                WHERE cve_id = :cve_id
            """)
            
            conn.execute(update_query, {'predicted_cwe': predicted_cwe, 'cve_id': cve_id})
        
        conn.commit()  # Commit all updates after the loop
    print("Database update complete!")

def predict():
    print("|| START PREDICTION PIPELINE ||")

    # Initialize the Postgre database information (user, name, password, host, port)
    db_name = "postgrescvedumper"
    db_user = "postgrescvedumper"
    db_password = "a42a18537d74c3b7e584c769152c3d"
    db_host = "127.0.0.1"
    db_port = "5432"

    # Create a connection to the Postgre database
    engine = create_connection(db_name, db_user, db_password, db_host, db_port)

    print()
    print("|| Collecting and preprocessing data ||")

    # Collect and preprocess the data from the database
    df_noinfo, df_filtered = data_processing(engine)

    # From the table with the CVEs with known assigned CWE(s), take the description and cwe_id column
    # The model is trained by connecting the description to the CWE(s)
    # This is done so that the model recognizes certain keywords that lead to the prediction of CWE(s) in other CVEs
    X = df_filtered['description']

    # Initialize the tokenizer
    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
    print("Data collected and preprocessed!")
    
    # Initialize a MultiLabelBinarizer
    mlb = MultiLabelBinarizer()

    # This transforms the labels (CWEs) into a binary representation
    # Ensure no missing values and convert to strings before splitting
    df_filtered['cwe_id'] = df_filtered['cwe_id'].fillna('').astype(str)
    labels = mlb.fit_transform(df_filtered['cwe_id'].str.split(','))

    # Convert the binary representation of the labels (CWEs) in a NumPy Array
    labels = np.array(labels)

    # Create a training set (80%) and validation set (20%) from the CVEs with known CWE(s) assigned.
    X_train, X_val, y_train, y_val = train_test_split(X, labels, test_size=0.2, random_state=42)
    
    # Initialize empty lists for the learning rate, batch size and weight decay
    learning_rate = []
    batch_size = []
    weight_decay = []

    # Depending on the flag, we perform hyperparameter tuning using multiple values that are tested. Each combination
    # will give results on the validation set. We recommend turning off the UPDATEDATABASE_FLAG
    if HYPERPARAMATERTUNING_FLAG:
        learning_rate = [1e-5, 2e-5, 5e-5]
        batch_size = [8, 16]
        weight_decay = [0, 0.01]
    else: # If the flag is False, use best combination of hyperparameter values
        learning_rate = [1e-5]
        batch_size = [16]
        weight_decay = [0.01]

    # Initialize our gridsearch for the different values for hyperparameters that we fine-tune
    gridSearch = list(itertools.product(
        learning_rate,
        batch_size,
        weight_decay
    ))

    # For every combination of learning rate, batch size and weight decay, train the model, validate and evaluate it
    for learning_rate, batch_size, weight_decay in gridSearch:
        print()
        print("|| Training and Evaluating Model with learning rate =", learning_rate, ", batch size =", batch_size, ", and weight decay =", weight_decay, " ||")

        train_loader = tokenize_and_prepare_dataloader(X_train, y_train, tokenizer, batch_size)
        val_loader = tokenize_and_prepare_dataloader(X_val, y_val, tokenizer, batch_size)

        # Determine if the use of CUDA on a GPU is available. If not, use the CPU (not recommended)
        device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Load in the distilbert-base-uncased model
        model = DistilBertForSequenceClassification.from_pretrained('distilbert-base-uncased', num_labels=labels.shape[1])
        model.to(device)

        # Initialize the AdamW optimizer
        optimizer = AdamW(model.parameters(), lr=learning_rate, weight_decay=weight_decay)
        criterion = torch.nn.BCEWithLogitsLoss()

        # Train the model in three epochs. For every epoch, print which epoch it is and what the loss is
        for epoch in range(3):
            train_loss = train(model, train_loader, optimizer, criterion, device)
            print(f"Epoch {epoch+1}, Loss: {train_loss}")
        
        # After training the model, validate it on the validation set. Report the accuracy, precision, recall and F1
        # scores and the hamming loss
        predictions, true_labels = evaluate(model, val_loader, device)
        print("Accuracy:", accuracy_score(true_labels, predictions))
        print("Precision Score: ", precision_score(true_labels, predictions, average='micro'))
        print("Recall Score: ", recall_score(true_labels, predictions, average='micro'))
        print("F1 Score:", f1_score(true_labels, predictions, average='micro'))
        print("Hamming Loss:", hamming_loss(true_labels, predictions))

        # Now, we create a dataloader for the test set, which is all the CVE descriptions with no assigned CWE(s)
        X_test = df_noinfo['description']
        inputs = tokenizer(X_test.tolist(), padding=True, truncation=True, return_tensors="pt", max_length=512)
        input_ids = inputs['input_ids']
        attention_mask = inputs['attention_mask']
        dataset = TensorDataset(input_ids, attention_mask)
        test_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)

        # Use the test_loader and trained model to evaluate the model on the test set.
        model.eval()
        predictions = []
        with torch.no_grad():
            for batch in test_loader:
                input_ids, attention_mask = [x.to(device) for x in batch]
                outputs = model(input_ids, attention_mask=attention_mask)
                logits = outputs.logits.detach().cpu().numpy()
                
                # In this evaluation, we only gather predictions, and no true labels (since we do not have them)
                predictions.extend(np.round(torch.sigmoid(torch.tensor(logits)).numpy()))

        # Convert predictions back to CWE label format and put them in a NumPy Array
        predictions_array = np.array(predictions)
        predicted_labels = mlb.inverse_transform(predictions_array)

        # Replace the 'NVD-CWE-noinfo' labels in df_noinfo with the predicted CWE(s) (only for actually predicted CWE(s))
        df_noinfo['cwe_id'] = [','.join(label) if label else 'NVD-CWE-noinfo' for label in predicted_labels]

        # Combine the two separate data frames back together
        final_df = pd.concat([df_filtered, df_noinfo], ignore_index=True)


        # Depending on the Flag, update the database
        if UPDATEDATABASE_FLAG:
            update_cwe_labels(engine, final_df)

        print()
        print("|| CWE Prediction System has completed succesfully! ||")

# When this script is directly called, run the main predict() function
predict()

