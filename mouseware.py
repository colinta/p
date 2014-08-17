import sys
import glob
from os.path import splitext, basename, dirname, join
import random
random = random.SystemRandom()

words = {}
src = join(dirname(__file__), 'txt/*')

for file in glob.glob(src):
    with open(file, 'r') as f:
        place = splitext(basename(file))[0]
        # using list(set( words )) unique-ifies the words
        words[place] = list(set([i.strip().lower() for i in f]))

construct = ['adjective', 'noun', 'verb', 'adjective', 'noun']


def generate():
    sentence = []
    for place in construct:
        sentence.append(random.choice(words[place]))
    return ' '.join(sentence)
