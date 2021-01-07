from collections import Counter
import random
import os
import numpy as np

class dataset(object):
    def __init__(self, root_c, root_blogs, lexer, vocab, sample_size=200):
        
        self.sample_size = sample_size
        self.vocab = vocab
        self.lexer = lexer

        self.data_c = self.load_dataset_c(root_c)
        self.data_blogs = self.load_dataset_blogs(root_blogs)
        print(len(self.data_c), len(self.data_blogs))

    def get_dataset(self, size=1000):
        """random.shuffle(self.data_c)
        random.shuffle(self.data_blogs)
        data = [(self.add_chars(self.data_blogs[i], prob=0.7),0) for i in range(size//4)] + [(self.add_text(self.data_c[i]),1) for i in range(size//2)] +\
            [(self.add_chars(self.data_blogs[i], prob=0),0) for i in range(size//4)] 
        random.shuffle(data)
        #print(data[0], "\n", data[1])
        return data"""

        random.shuffle(self.data_blogs)
        random.shuffle(self.data_c)
        temp = [(self.add_text(self.random_split(self.data_c[i])),1) for i in range(size//2)]
        temp2 = [(self.random_split(self.data_blogs[i]),0) for i in range(size//2)]#[(np.random.permutation(t),0) for t in temp]
        temp3 = [("".join(np.random.permutation(list(self.random_split(self.data_c[i])))),0) for i in range(size//2)]
        data = temp + temp2 + temp3
        random.shuffle(data)
        return data
        #print(data[0], "\n", data[1])
    
    def random_split(self, sample):
        try:
            length = np.random.randint(len(sample)//4, len(sample))
            start = np.random.randint(0, len(sample) - length)
            return sample[start:start+length]
        except:
            return sample

    def add_text(self, sample, prob=0.25):
        num = np.random.choice(int(1/prob),1)
        if (num[0] == 0):
            index = np.random.choice(len(self.data_blogs),1)
            num = np.random.choice(2,1)
            if (num[0] == 0):
                sample = sample + self.random_split(self.data_blogs[index[0]])
            else:
                sample = self.random_split(self.data_blogs[index[0]]) + sample
        return sample

    def add_chars(self, sample, prob=0.3):
        num = np.random.choice(int(len(sample)*prob) + 1,1)
        if num[0] > 0:
            indices = np.random.choice(len(sample), num[0])
            #special_sym = np.random.choice(len(self.vocab), len(indices))
            syms = ["EQUAL","APAS","EXCL", "TILDA","MINUS","PLUS","MULT","LESS","GREATER"]
            special_sym = np.random.choice(len(syms) + 30, len(indices))
            for j in range(len(indices)):
                if (special_sym[j] < 10):
                    a = "SC"
                elif (special_sym[j] < 20):
                    a = "OPEN1"
                elif (special_sym[j] < 30):
                    a = "CLOSE1"
                else:
                    a = syms[special_sym[j] - 30]
                sample[indices[j]] = a
        return sample
    
    def generate_tokens(self, sample, prob=0.7):
        num = np.random.choice(int(len(sample)*prob) + 1,1)
        if num[0] > 0:
            indices = np.random.choice(len(sample), num[0])
            for j in range(len(indices)):
                sample[indices[j]] = 'NAME'
        return sample


    def load_dataset_c(self, root):
        data = []
        print(root)
        dirs = [root]
        while (len(dirs) > 0): 
            root = dirs.pop(0)
            
            for filename in os.listdir(root):
                filename = root + "/" + filename
                if filename.endswith(".c") or filename.endswith(".h"):
                    try:
                        with open(filename, 'r') as f:
                            data.append(f.read())
                            continue
                    except:
                        continue

                elif os.path.isdir(filename):
                    dirs.append(filename)
                
        return data

    def load_dataset_blogs(self, root):
        data = []
        print(root)
        dirs = [root]
        while (len(dirs) > 0): 
            root = dirs.pop(0)
            
            for filename in os.listdir(root):
                filename = root + "/" + filename
                if os.path.isdir(filename):
                    dirs.append(filename)
                else:
                    try:
                        with open(filename, 'r') as f:
                            data.append(f.read())
                            continue
                    except:
                        continue
                
        return data


def load_datasets(c_train_path, b_train_path, c_dev_path, b_dev_path, lexer, vocab):
    return dataset(c_train_path, b_train_path, lexer, vocab), dataset(c_dev_path, b_dev_path, lexer, vocab)

def encode_input(text, vocab):
    return torch.tensor([vocab.index(token) for token in text], dtype=torch.long, device=device).view(-1, 1)
