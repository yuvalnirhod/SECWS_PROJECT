from pickle import load
from sklearn.pipeline import Pipeline
import os
import pandas as pd


def preprocess(x):
    return pd.Series(x).replace(r'\b([A-Za-z])\1+\b', '', regex=True)\
        .replace(r'\b[A-Za-z]\b', '', regex=True)

transformer = load(open('./preprocessing.pkl', 'rb'))
vectorizer = load(open('./vectorizer.pkl', 'rb'))
clf = load(open('./model.pkl', 'rb'))

pipe_RF = Pipeline([
    ('preprocessing', transformer),
    ('vectorizer', vectorizer),
    ('clf', clf)]
)

while True:
    file_name = input("Enter file name: ")
    if (os.path.isfile(file_name)):
        with open(file_name, "r") as f:
            data = f.read()
            decoded_label = pipe_RF.predict(data)
            print(preprocess(data))

            if (decoded_label[0] == 1):
                print("YES! this is a c file.")
            else:
                print("NO! this is not a c file.")
    else:
        print("No such file!")

