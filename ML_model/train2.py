import pandas as pd
from Getting_dataset import *

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import FunctionTransformer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from pickle import dump, load
import sys
# Loading Data

data_obj = dataset("/home/fw/Downloads/code", "/home/fw/Downloads/text", [], [])
print("Searched dirs")
data = data_obj.get_dataset(25000)
# Train/Test split
content = [t[0] for t in data]
language = [t[1] for t in data]
X, y = content, language
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

print("Finished loading data")
# Model params
token_pattern = r"""(\b[A-Za-z_]\w*\b|[!\#\$%\&\*\+:\-\./<=>\?@\\\^_\|\~]+|[ \t\(\),;\{\}\[\]`"'])"""

def preprocess(x):
    return pd.Series(x).replace(r'\b([A-Za-z])\1+\b', '', regex=True)\
        .replace(r'\b[A-Za-z]\b', '', regex=True)

print("Tokanized data")

# Pipe steps
transformer = FunctionTransformer(preprocess)
vectorizer = TfidfVectorizer(token_pattern=token_pattern, max_features=3000)
clf = RandomForestClassifier(n_jobs=4)

pipe_RF = Pipeline([
    ('preprocessing', transformer),
    ('vectorizer', vectorizer),
    ('clf', clf)]
)

# Setting best params
best_params = {
    'clf__criterion': 'gini',
    'clf__max_features': 'sqrt',
    'clf__min_samples_split': 3,
    'clf__n_estimators': 300
}

pipe_RF.set_params(**best_params)

print("Training")
# Fitting
pipe_RF.fit(X_train, y_train)

print("Evaluating")
# Evaluation
print('Accuracy: ' + str(pipe_RF.score(X_test, y_test)))

dump(transformer, open('preprocessing.pkl','wb'))
dump(vectorizer, open('vectorizer.pkl','wb'))
dump(clf, open('model.pkl','wb'))

