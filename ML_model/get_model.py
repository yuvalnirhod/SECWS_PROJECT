from pickle import load
from sklearn.pipeline import Pipeline
import os
import pandas as pd




def get_model():

    def preprocess(x):
        return pd.Series(x).replace(r'\b([A-Za-z])\1+\b', '', regex=True)\
            .replace(r'\b[A-Za-z]\b', '', regex=True)

    transformer = load(open('./ML_model/preprocessing.pkl', 'rb'))
    vectorizer = load(open('./ML_model/vectorizer.pkl', 'rb'))
    clf = load(open('./ML_model/model.pkl', 'rb'))

    pipe_RF = Pipeline([
        ('preprocessing', transformer),
        ('vectorizer', vectorizer),
        ('clf', clf)]
    )

    return pipe_RF