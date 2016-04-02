from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import datetime

engine = create_engine('sqlite:///recaptcha.db')

#Declare an instance of the Base class for mapping tables
Base = declarative_base()

#Map a table to a class by inheriting base class
class Types(Base):
    __tablename__ = 'types'

    id = Column(Integer, primary_key=True)
    text = Column(Text, nullable=False)

    def __init__(self, text):
        self.text = text

    def __str__(self):
        return "Type(id: {}, text: {})".format(self.id, self.text)

class Captcha(Base):
    __tablename__ = 'captcha'

    id = Column(Integer, primary_key=True)
    md5 = Column(String(32), nullable=False)
    phash = Column(String(16), nullable=False)
    type_id = Column(Integer, nullable=False)
    histogram = Column(postgresql.ARRAY(Float), nullable=False)
    max1 = Column(Integer, nullable=False)
    max2 = Column(Integer, nullable=False)
    min1 = Column(Integer, nullable=False)
    min2 = Column(Integer, nullable=False)
    popularity = Column(Integer, nullable=False)
    failures = Column(Integer, nullable=False)
    creation_date = Column(DateTime, nullable=False)

    def __init__(self, type_id, md5, phash, histogram, min, max, popularity = 1, failures = 0):
        self.type_id = type_id
        self.md5 = md5
        self.phash = phash
        self.histogram = histogram

        if len(min) == 0:
            self.min1 = 1000
        else:
            self.min1 = min[0]
        if len(min) == 1:
            self.min2 = 1000
        else:
            self.min2 = min[1]

        if len(max) == 0:
            self.max1 = 1000
        else:
            self.max1 = max[0]
        if len(max) == 1:
            self.max2 = 1000
        else:
            self.max2 = max[1]
        self.popularity = popularity
        self.failures = failures
        self.creation_date = datetime.datetime.now()

    def __str__(self):
        return "Captcha(id: {}, typeId: {}, md5: {} mins: {},{} maxs: {},{} pop: {} fails: {} created: {})".format(
            self.id, self.type_id, self.md5, self.min1, self.min2, self.max1, self.max2, self.popularity, self.failures,
            self.creation_date)

class Captcha_Groups(Base):
    __tablename__ = "captcha_groups"

    id = Column(Integer, ForeignKey('captcha.id'), primary_key=True)
    type_id = Column(Integer, nullable=False)
    group = Column(postgresql.ARRAY(Integer))
    captcha = relationship(Captcha)

    def __init__(self, captcha_id, type_id, group = []):
        self.id = captcha_id
        self.type_id = type_id
        self.group = group

    def __str__(self):
        return "Captcha Group(id: {}, type: {}, group: {})".format(self.id, self.type_id, self.group)

#Create the table using the metadata attribute of the base class
Base.metadata.create_all(engine)

Session = sessionmaker(bind=engine)
session = Session()
