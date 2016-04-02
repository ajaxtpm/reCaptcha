import os, sys
import json
import requests
import base64
import re
import PIL
from PIL import Image
from hashlib import md5
import time, datetime
import signal
from utils import translate, get_instructions_hash
import dbmodels
from hash import CaptchaHash, ImageHash


class Stats:
    def __init__(self):
        self.STATS_IDS_CHECKED = 0
        self.STATS_NEW_TYPES = 0
        self.STATS_NEW_IMAGES = 0
        self.STATS_IMAGES_ALREADY_STORED = 0
        self.STATS_IMAGES_GROUPED = 0
        self.STATS_WRONG_SIZE_IMAGE = 0
        self.STATS_WRONG_TEXT = 0
        self.STATS_OTHER_ERRORS = 0
        self.STATS_SOLVED_CAPTCHAS = 0
        self.STATS_FAILED_CAPTCHAS = 0
        self.STATS_ERRORS_FIXED = 0
        self.STATS_TARGET_IMAGES = 0
        self.STATS_NONTARGET_IMAGES = 0
        self.start_time = datetime.datetime.now()
        self.solved_types = {}

    def new_id(self, count = 1): self.STATS_IDS_CHECKED += count
    def new_type(self, count = 1): self.STATS_NEW_TYPES += count
    def new_image(self, count = 1): self.STATS_NEW_IMAGES += count
    def new_image_already_stored(self, count = 1): self.STATS_IMAGES_ALREADY_STORED += count
    def new_image_grouped(self, count = 1): self.STATS_IMAGES_GROUPED += count
    def wrong_size(self, count = 1): self.STATS_WRONG_SIZE_IMAGE += count
    def wrong_text(self, count = 1): self.STATS_WRONG_TEXT += count
    def solved_captcha(self, count = 1): self.STATS_SOLVED_CAPTCHAS += count
    def failed_captcha(self, count = 1): self.STATS_FAILED_CAPTCHAS += count
    def error_fixed(self, count = 1): self.STATS_ERRORS_FIXED += count
    def other_error(self, count = 1): self.STATS_OTHER_ERRORS += count
    def target_images(self, count = 1): self.STATS_TARGET_IMAGES += count
    def nontarget_images(self, count = 1): self.STATS_NONTARGET_IMAGES += count
    def solved_type(self, type):
        if type in self.solved_types:
            self.solved_types[type] += 1
        else:
            self.solved_types[type] = 1

    def output(self):
        print "\nStatistics:\nStarted: {}\n===========\n".format(self.start_time)
        print "IDs Checked: {}\nNew types added: {}\nNew images saved: {}\nNew images alread stored: {}\nNew images grouped: {}\n" \
              "Images with wrong size: {}\nWrong text instructins: {}\nOther errors: {}\nTime elapsed: {}s\n\nSolved captchas: {}\n" \
              "Failed captchas: {}\nErrors fixed: {}\nTarget images: {}\nNon-Target images: {}\n\nSolved types:".format(
            self.STATS_IDS_CHECKED, self.STATS_NEW_TYPES, self.STATS_NEW_IMAGES, self.STATS_IMAGES_ALREADY_STORED, self.STATS_IMAGES_GROUPED,
            self.STATS_WRONG_SIZE_IMAGE, self.STATS_WRONG_TEXT, self.STATS_OTHER_ERRORS, str(datetime.datetime.now() - self.start_time),
            self.STATS_SOLVED_CAPTCHAS, self.STATS_FAILED_CAPTCHAS, self.STATS_ERRORS_FIXED, self.STATS_TARGET_IMAGES, self.STATS_NONTARGET_IMAGES)
        all_types = sum(self.solved_types.values())
        for type in self.solved_types:
            print "{}: {}   ({:.4}%)".format(type, self.solved_types[type], 100. * float(self.solved_types[type]) / float(all_types))


statistics = Stats()
OLDEST_ID_URL = '...'
CAPTCHAS_API_URL = '...'
BAD_INSTRUCTIONS = ['):']
INSTRUCTION_SUBSTITUTE_PATTERNS = {
    'Verify\r\nReport a problem': '(\.\r\n)?Verify\r\nReport a problem.*',
    'Please select all matching images': '(.\r\n)?Please select all matching images.*',
    'Multiple correct solutions required - please solve more': '(\.\r\n)?Multiple correct solutions required - please solve more.*',
}
CREATE_NEW_TYPES = False



def merge_instructions_hash(instructions, path = 'instructions.txt'):
    file_instr = get_instructions_hash(path)
    f = open(path, 'a')
    for id in set(instructions.keys()) - set(file_instr.keys()):
        text = instructions[id]
        text = text.replace('\n', '').replace('\r', '')
        f.write("{}:{}\n".format(id, text))
        if not os.path.exists('captchas/{}'.format(id)):
            os.makedirs('captchas/{}'.format(id))
    f.flush()
    f.close()

def check_text_instruction(text):
    global statistics

    if text:
        if type(text) == unicode:
            text = text.encode('utf8')
        if text:
            for pattern in INSTRUCTION_SUBSTITUTE_PATTERNS:
                if text.find(pattern):
                    text = re.sub(INSTRUCTION_SUBSTITUTE_PATTERNS[pattern], '', text)
            bad_instr = False
            for instr in BAD_INSTRUCTIONS:
                if text.find(instr) != -1:
                    bad_instr = True
                    break
            if bad_instr:
                statistics.wrong_text()
                print "[*] Bad string found"
                return None
        return translate(text).strip()
    return text

def get_instruction_id(instructions, text):
    for id in instructions.keys():
        if instructions[id] == text:
            return id
    return -1

def final():
    global statistics
    statistics.output()
    f = open('logs/'+str(datetime.datetime.now()) + '.txt', 'w')
    old_stdout = sys.stdout
    sys.stdout = f
    statistics.output()
    sys.stderr = old_stdout
    f.close()

def exit_handler(signal, frame):
    final()
    sys.exit(0)

def match_captcha(images):
    matches = {}
    for image_hash in images:
        matches[image_hash] = None
        query = dbmodels.session.query(dbmodels.Captcha).filter_by(md5 = image_hash.md5).filter(
            dbmodels.Captcha.popularity > dbmodels.Captcha.failures).order_by(dbmodels.Captcha.popularity.desc())
        if query.count() > 0:
            matches[image_hash] = query.first()
            continue

        query = dbmodels.session.query(dbmodels.Captcha_Groups).join(dbmodels.Captcha).filter(
            dbmodels.Captcha.max1 > image_hash.maxs[0] - 2).filter(
            dbmodels.Captcha.max1 < image_hash.maxs[0] + 2).filter(
            dbmodels.Captcha.max2 > image_hash.maxs[1] - 2).filter(
            dbmodels.Captcha.max2 < image_hash.maxs[1] + 2).filter(
            dbmodels.Captcha.min1 > image_hash.mins[0] - 2).filter(
            dbmodels.Captcha.min1 < image_hash.mins[0] + 2).filter(
            dbmodels.Captcha.min2 > image_hash.mins[1] - 2).filter(
            dbmodels.Captcha.min2 < image_hash.mins[1] + 2).filter(
            dbmodels.Captcha.popularity > dbmodels.Captcha.failures)
        for group in query.all():
            ihash = ImageHash.create_from_db(group.captcha.phash, group.captcha.histogram)
            if ImageHash.phash_diff(ihash.phash, image_hash.phash) < 14:
                if ImageHash.aver_squad_diff(ihash.histogram[:], image_hash.histogram[:]) < 5:
                    matches[image_hash] = group.captcha
                    break
    return matches

def solve_captcha(instr_id, images):
    solution = []
    for image_hash in images:
        query = dbmodels.session.query(dbmodels.Captcha).filter_by(md5 = image_hash.md5, type_id = instr_id).filter(
            dbmodels.Captcha.popularity > dbmodels.Captcha.failures)
        if query.count() > 0:
            solution.append(images.index(image_hash))
            continue

        query = dbmodels.session.query(dbmodels.Captcha_Groups).join(dbmodels.Captcha).filter(
            dbmodels.Captcha.type_id == instr_id).filter(
            dbmodels.Captcha.max1 > image_hash.maxs[0] - 2).filter(
            dbmodels.Captcha.max1 < image_hash.maxs[0] + 2).filter(
            dbmodels.Captcha.max2 > image_hash.maxs[1] - 2).filter(
            dbmodels.Captcha.max2 < image_hash.maxs[1] + 2).filter(
            dbmodels.Captcha.min1 > image_hash.mins[0] - 2).filter(
            dbmodels.Captcha.min1 < image_hash.mins[0] + 2).filter(
            dbmodels.Captcha.min2 > image_hash.mins[1] - 2).filter(
            dbmodels.Captcha.min2 < image_hash.mins[1] + 2).filter(
            dbmodels.Captcha.popularity > dbmodels.Captcha.failures)
        for group in query.all():
            ihash = ImageHash.create_from_db(group.captcha.phash, group.captcha.histogram)
            if ImageHash.phash_diff(ihash.phash, image_hash.phash) < 14:
                if ImageHash.aver_squad_diff(ihash.histogram[:], image_hash.histogram[:]) < 5:
                    solution.append(images.index(image_hash))
                    break
    return solution


if __name__ == "__main__":
    # temporary file to figure out what the hell is going on with crontab
    with open('runs.txt', 'a') as f:
        f.write(str(datetime.datetime.now()) + "\n")

    lastidfile = 'lastid.txt'
    current_id = 0
    if not os.path.exists(lastidfile):
        print "[!] No {lastidfile} file here"
    else:
        with open(lastidfile) as f:
            current_id = int(f.read().strip())

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGQUIT, exit_handler)

    instructions_hash = get_instructions_hash()

    current_id = 0
    req = requests.get(OLDEST_ID_URL)
    if req.ok:
        id = json.loads(req.text)['id']
        if current_id == 0:
            current_id = id
        elif current_id == id:
            print "[*] No ids to check"
            exit(0)

    try:
        while current_id:
            try:
                req = requests.get(CAPTCHAS_API_URL.format(current_id))
            except: pass
            if req and req.ok:
                data = json.loads(req.text)
                if type(data) is dict:
                    ids = sorted(map(lambda x: int(x), data.keys()))
                    for id in ids:
                        statistics.new_id()
                        current_id = str(id)
                        captcha_data = data[str(id)]
                        text_instructions = check_text_instruction(captcha_data['textinstructions'])
                        if text_instructions:
                            image_base64 = captcha_data['image']
                            if len(image_base64) >= 100 and image_base64.find(',') > 0:
                                image_bytes = base64.b64decode(image_base64.split(',')[1])

                                #ToDo: only one thread possible there!
                                with open('temp/temp.jpeg', 'wb') as f:
                                    f.write(image_bytes)
                                try:
                                    img = Image.open('temp/temp.jpeg')
                                except:
                                    statistics.other_error()

                                if img and (img.size == (300, 300) or img.size == (400, 400)):
                                    #Merge instructions there in order to avoid good instructions without a picture
                                    instr_id = -1
                                    query = dbmodels.session.query(dbmodels.Types).filter_by(text = text_instructions)
                                    if query.count() == 0:
                                        if CREATE_NEW_TYPES:
                                            statistics.new_type()
                                            print "[*] [{}] New captcha type: {}".format(current_id, text_instructions)
                                            new_type = dbmodels.Types(text_instructions)
                                            dbmodels.session.add(new_type)
                                            dbmodels.session.commit()
                                            instr_id = new_type.id
                                        else:
                                            print "[!] [{}] Creation of new types is disabled".format(current_id)
                                            continue
                                    else:
                                        instr_id = query.first().id

                                    captcha_answer = captcha_data['code']
                                    if captcha_answer.find('click') >= 0:
                                        indexes = re.findall('\d+', captcha_answer)
                                        indexes = map(lambda x: int(x) - 1, indexes)
                                        if indexes:
                                            images = []
                                            for index in range(img.size[0] * img.size[1] / 10000):
                                                try:
                                                    width = (index % (img.size[0] / 100)) * 100
                                                    height = (index / (img.size[0] / 100)) * 100
                                                    cropped = img.crop((width, height, width+100, height+100))
                                                    images.append(CaptchaHash(cropped))
                                                except:
                                                    statistics.other_error()

                                            matches = match_captcha(images)
                                            matches = {images.index(x): matches[x] for x in matches.keys()}
                                            solution = [x for x in matches.keys() if matches[x] and matches[x].type_id == instr_id]
                                            print "Matched {} of {} ({:.4}%)".format(len(solution), len(matches), float(100 * len(solution))/ float(len(matches)))
                                            for match in matches:
                                                if matches[match]:
                                                    print "{}: type id {}".format(match, matches[match].type_id)
                                                else:
                                                    print "{}: didnt matched to any".format(match)
                                            statistics.target_images(len([x for x in matches.keys() if matches[x] and matches[x].type_id == instr_id]))
                                            statistics.nontarget_images(len([x for x in matches.keys() if matches[x] and matches[x].type_id != instr_id]))

                                            solution = solve_captcha(instr_id, images)

                                            # prediction = (success, failed, overall)
                                            prediction = (len(set(solution).intersection(set(indexes))),
                                                          len(set(solution) ^ set(indexes)),
                                                          len(set(solution).union(set(indexes))))

                                            if prediction[0] > prediction[1]:
                                                print "[+] Solved captcha (type: {})  ({:.4}%): {} - {}".format(instr_id,
                                                    100 * float(prediction[0])/float(prediction[2]), indexes, solution)
                                                statistics.solved_captcha()
                                                statistics.solved_type(text_instructions)
                                            else:
                                                print "[+] Failed captcha (type: {})  ({:.4}%): {} - {}".format(instr_id,
                                                    100 * float(prediction[0])/float(prediction[2]), indexes, solution)
                                                statistics.failed_captcha()

                                            for index in range(img.size[0] * img.size[1] / 10000):
                                                try:
                                                    image_hash = images[index]
                                                    query = dbmodels.session.query(dbmodels.Captcha).filter_by(
                                                        md5 = image_hash.md5, type_id = instr_id)
                                                    if query.count():
                                                        if index in indexes:
                                                            statistics.new_image_already_stored()
                                                            print "[!] [{}] The image is already storing: {}".format(current_id, image_hash.md5)
                                                            query.first().popularity += 1
                                                            dbmodels.session.commit()
                                                        else:
                                                            statistics.error_fixed()
                                                            print "[+] [{}] Image stores with incorrect type: {}".format(current_id, image_hash.md5)
                                                            query.first().failures += 1
                                                            dbmodels.session.commit()
                                                    elif index in solution and not index in indexes:
                                                        # Counter-captcha is an image which purpose is to prevent future false matches of
                                                        # images that were marked as solution by grouping feature.
                                                        # Thus counter-captcha should have popularity = 0 and failures = 1 (>0)
                                                        print "[+] [{}] Anti-captcha image: {}".format(current_id, image_hash.md5)
                                                        captcha = dbmodels.Captcha(instr_id, image_hash.md5, str(image_hash.phash),
                                                            image_hash.histogram, image_hash.mins, image_hash.maxs, 0, 1)
                                                        dbmodels.session.add(captcha)
                                                        dbmodels.session.commit()
                                                    elif index in indexes:
                                                        statistics.new_image()

                                                        print "[+] [{}] Saved image: {}".format(current_id, image_hash.md5)
                                                        captcha = dbmodels.Captcha(instr_id, image_hash.md5, str(image_hash.phash),
                                                            image_hash.histogram, image_hash.mins, image_hash.maxs)
                                                        dbmodels.session.add(captcha)
                                                        dbmodels.session.commit()

                                                        matched = False
                                                        query = dbmodels.session.query(dbmodels.Captcha_Groups).join(dbmodels.Captcha).filter(
                                                            dbmodels.Captcha.type_id == captcha.type_id).filter(
                                                            dbmodels.Captcha.max1 > image_hash.maxs[0] - 2).filter(
                                                            dbmodels.Captcha.max1 < image_hash.maxs[0] + 2).filter(
                                                            dbmodels.Captcha.max2 > image_hash.maxs[1] - 2).filter(
                                                            dbmodels.Captcha.max2 < image_hash.maxs[1] + 2).filter(
                                                            dbmodels.Captcha.min1 > image_hash.mins[0] - 2).filter(
                                                            dbmodels.Captcha.min1 < image_hash.mins[0] + 2).filter(
                                                            dbmodels.Captcha.min2 > image_hash.mins[1] - 2).filter(                                                                dbmodels.Captcha.min2 < image_hash.mins[1] + 2)
                                                        for group in query.all():
                                                            ihash = ImageHash.create_from_db(group.captcha.phash, group.captcha.histogram)
                                                            if ImageHash.phash_diff(ihash.phash, image_hash.phash) < 14:
                                                                if ImageHash.aver_squad_diff(ihash.histogram[:], image_hash.histogram[:]) < 5:
                                                                    matched = True
                                                                    group.group = group.group + [captcha.id]
                                                                    dbmodels.session.commit()
                                                                    print "[+]   [{}] Matched to captcha id {}".format(current_id, group.id)
                                                                    statistics.new_image_grouped()

                                                                    break

                                                        if not matched:
                                                            group = dbmodels.Captcha_Groups(captcha.id, captcha.type_id)
                                                            dbmodels.session.add(group)
                                                            dbmodels.session.commit()
                                                except:
                                                    statistics.other_error()
                                        else:
                                            print "[!][{}] No indexes in code: {}".format(current_id, captcha_answer)
                                    else:
                                        print "[!][{}] Bad captcha answer: {}".format(current_id, captcha_answer)
                                else:
                                    statistics.wrong_size()
                                    print "[!][{}] Non standart image size: {}".format(current_id, img.size)
                            else:
                                statistics.other_error()
                                print "[!][{}] Too short image base64: {}".format(current_id, len(image_base64))
                        else:
                            print "[!][{}] No text instructions".format(current_id)

                    with open(lastidfile, 'w') as f:
                        f.write(str(max(ids)))
                else:
                    print "[!] Got not dictionary: {}".format(type(data))
                    break
    except:
        print "[!] Very bad exception!"

    final()
