# -*- coding: utf-8 -*-
import re
import numpy

def get_instructions_hash(path = 'instructions.txt'):
    instructions = {}
    f = open(path, 'r')
    for line in f.read().split('\n'):
        if line:
            (id, text) = line.split(':', 1)
            id = int(id)
            instructions[id] = text
    f.close()
    return instructions

EXTRACTION_PATTERNS = [
    'ENG: *([^-.]+)',
    ' / (.+?)\.?$',
    'all (?:the )?(?:images |pictures |squares )?(?:with |are |of )?(?:a |the |an )?([^-.]+)',
    'все (?:изображения|квадраты),? (?:на которых |где |с |со )(?:есть )?([^-.]+)'
]

def translate(text):
    res = text
    for pattern in EXTRACTION_PATTERNS:
        match = re.search(pattern, res)
        if match and match.group(0):
            res = match.group(1)
    return re.sub('_', ' ', res)


def smooth(x,window_len=11,window='hanning'):
    if x.ndim != 1:
        raise ValueError, "smooth only accepts 1 dimension arrays."
    if x.size < window_len:
        raise ValueError, "Input vector needs to be bigger than window size."

    if window_len<3:
        return x

    if not window in ['flat', 'hanning', 'hamming', 'bartlett', 'blackman']:
        raise ValueError, "Window is on of 'flat', 'hanning', 'hamming', 'bartlett', 'blackman'"
    s=numpy.r_[x[window_len-1:0:-1],x,x[-1:-window_len:-1]]
    #print(len(s))
    if window == 'flat': #moving average
        w=numpy.ones(window_len,'d')
    else:
        w=eval('numpy.'+window+'(window_len)')

    y=numpy.convolve(w/w.sum(),s,mode='valid')
    return y

if __name__ == '__main__':
    f = open('instructions.txt')
    lines = []
    for line in f.read().split('\n'):
        if line:
            (id, t) = line.split(':', 1)
            lines.append(t)

    for line in lines:
        print "Was <{}> become <{}>".format(line, translate(line))
