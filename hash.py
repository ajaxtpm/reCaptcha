import os, sys
import imagehash
from PIL import Image
from hashlib import md5
import matplotlib.pyplot as plt
import numpy as np
import math
import operator
import time, datetime
import utils
from scipy.signal import argrelextrema
import dbmodels

class ImageHash:
    def __init__(self, phash, histogram):
        self.phash = phash
        self.histogram = histogram

    @staticmethod
    def create_from_db(phash, histogram):
        return ImageHash(phash, np.array(histogram))

    @staticmethod
    def aver_squad_diff(one, two):
        if len(one) == len(two):
            return math.sqrt(reduce(operator.add, list(map(lambda a,b: (a-b)**2, one, two))) / len(one))
        return -1

    @staticmethod
    def phash_diff(one, two):
        return bin(int(one, 16) ^ int(two, 16)).count('1')


class CaptchaHash(ImageHash):
    def __init__(self, path):
        t = path
        if type and path.__class__ == str:
            t = Image.open(path)
        phash = imagehash.phash(t, 8)
        histogram = np.array(t.convert('L').histogram())
        self.md5 = md5(t.tostring()).hexdigest()

        self.phash = str(phash)
        self.histogram = utils.smooth(histogram, 100)

        self.mins = argrelextrema(self.histogram, np.less)[0]
        self.maxs = argrelextrema(self.histogram, np.greater)[0]
        self.histogram = np.array(map(lambda x: int(x), self.histogram))

        if len(self.mins) < 2: self.mins = np.append(self.mins, [1000] * (2-len(self.mins)) )
        if len(self.maxs) < 2: self.maxs = np.append(self.maxs, [1000] * (2-len(self.maxs)) )

    def __str__(self):
        return '{}, <{}, {}>'.format(self.phash, self.mins, self.maxs)
