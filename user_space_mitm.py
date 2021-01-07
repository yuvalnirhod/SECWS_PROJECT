#!/usr/bin/env python3
import multiprocessing 
import NIFI_user_space
import FTP_user_space
import HTTP_user_space
import SMTP_user_space
from pickle import load
from sklearn.pipeline import Pipeline
import os
import pandas as pd

def preprocess(x):
        return pd.Series(x).replace(r'\b([A-Za-z])\1+\b', '', regex=True)\
            .replace(r'\b[A-Za-z]\b', '', regex=True)

def get_model():
    transformer = load(open('./ML_model/preprocessing.pkl', 'rb'))
    vectorizer = load(open('./ML_model/vectorizer.pkl', 'rb'))
    clf = load(open('./ML_model/model.pkl', 'rb'))

    pipe_RF = Pipeline([
        ('preprocessing', transformer),
        ('vectorizer', vectorizer),
        ('clf', clf)]
    )

    return pipe_RF

def start():
    model1 = get_model()
    model2 = get_model()
    stop_threads = False
    process = []
    process.append(multiprocessing.Process(target=NIFI_user_space.main, args=()))
    process.append(multiprocessing.Process(target=FTP_user_space.main, args=()))
    process.append(multiprocessing.Process(target=HTTP_user_space.main, args=(model1,)))
    process.append(multiprocessing.Process(target=SMTP_user_space.main, args=(model2,)))

    for p in process:
        p.start()

    input('Press "ENTER" to exit')

    for p in process: 
        p.terminate() 

    print("FINISHED!")


start()