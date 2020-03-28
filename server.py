#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pip3 install validate_email
# pip3 install flask-login
from flask_caching import Cache
import traceback
from datetime import datetime, timedelta, time
from pymongo import MongoClient
from bson.objectid import ObjectId
import flask
import flask_login
import hashlib
from validate_email import validate_email
from twilio.rest import Client
import sendgrid
from sendgrid.helpers.mail import *
import configparser

# Import config variables
config = configparser.ConfigParser()
config.read('config.ini')

# Initialize Twilio client
twilioClient = Client(config.get('APP', 'TWILIO_ACCOUNT_SID'), config.get('APP', 'TWILIO_AUTH_TOKEN'))

# Initialize Email client
sg = sendgrid.SendGridAPIClient(api_key=config.get('APP', 'SENDGRID_API_KEY'))
from_email = Email(config.get('EMAIL', 'FROM'))
subject = "Jött egy segítségkérés a számodra!"
subject_utf8 = subject.decode('UTF-8')

BASE_URL = config.get('APP', 'BASE_URL')

app = flask.Flask(__name__)
app.config['REMEMBER_COOKIE_NAME']="https://segitseg.info"
app.secret_key = config.get('APP', 'SECRET_KEY')


login_manager = flask_login.LoginManager()

login_manager.init_app(app)

client = MongoClient(config.get('DATABASE', 'URL'))

db = client.segitseg

cache = Cache(config={'CACHE_TYPE': 'simple'})
cache.init_app(app)


def getHelpType(id):
    return db.helpType.find_one({"_id": id})

def getCity(id):
    return db.city.find_one({"_id": id})


def getHelpTypesOnkentes():
    helpTypes = []
    if len(helpTypes) == 0:
        for c in db.helpType.find({"type": {"$in": ["onkentes"]}}):
            helpTypes.append(c["_id"])
    return helpTypes


def getHelpTypesTavsegitseg():
    helpTypes = []
    if len(helpTypes) == 0:
        for c in db.helpType.find({"tavsegitseg": True}):
            helpTypes.append(ObjectId(c["_id"]))
    return helpTypes


def getHelpTypeNamesAll():
    helpTypes = {}
    if len(helpTypes) == 0:
        for c in db.helpType.find():
            helpTypes[c["_id"]]=c["name"];
    return helpTypes

def sendEmail(email, helpType):
    to_email = To(email)
    ht = helpType.encode('utf-8')
    body = "Szia, \n\nTaláltunk számodra egy feladatot " + ht + " témakörben.\n\nKérlek, látogass el a https://segitseg.info/segitek oldalra hogy tudj segíteni :)\n\nÜdvözlettel: a Segitseg.info csapata"
    body_utf8 = body.decode('utf-8')
    content = Content("text/plain", body_utf8)
    mail = Mail(from_email, to_email, subject, content)
    return sg.client.mail.send.post(request_body=mail.get())

# ******************************************************************************
# SMS VERIFICATION
# ******************************************************************************

VERIFICATION_SID = config.get('APP', 'VERIFICATION_SID')

def start_verification(to):

    service = VERIFICATION_SID

    verification = twilioClient.verify \
        .services(service) \
        .verifications \
        .create(to=to, channel='sms')

    return verification.sid


def check_verification(phone, code):
    service = VERIFICATION_SID

    return twilioClient.verify \
        .services(service) \
        .verification_checks \
        .create(to=phone, code=code)


# ******************************************************************************
# LOGIN / AUTH
# ******************************************************************************

class User(flask_login.UserMixin):
    pass


def hashPassword(password):
    m = hashlib.sha256()
    m.update(password.encode('utf-8'))
    return str(m.hexdigest())


def getUserFromDB(email):
    userModel = db.user.find_one({'_id': email})
    if userModel is None:
        return
    user = User()
    user.model = userModel
    user.id = email
    user.name = userModel['name']
    user.city = userModel['city']
    user.phone = userModel['phone']
    user.hash = userModel['hash']
    user.approved = userModel['approved']
    user.tavsegitseg = userModel['tavsegitseg']

    list = []
    osszesTavsegitseg = getHelpTypesTavsegitseg()
    for e in userModel['helpTypes']:
        list.append(ObjectId(e))
    user.helpTypes=list

    return user


@login_manager.user_loader
def user_loader(email):
    return getUserFromDB(email)


@login_manager.request_loader
def request_loader(request):
    if 'email' not in request.form:
        return
    user = getUserFromDB(request.form.get('email'))
    #if user is not None:
    #    user.is_authenticated = 'password' in request.form if hashPassword(request.form['password']) == user.hash else False
    return user

def redirectLoggedUsers(codePage = False):
    print("Check user")
    if flask_login.current_user.is_authenticated:
        if flask_login.current_user.approved:
            print("Redirect to segitek")
            return flask.redirect(BASE_URL+'/segitek')
        else:
            if not codePage:
                print("Redirect to code")
                return flask.redirect(BASE_URL+'/code')
    return None


@app.route('/', methods=['GET'])
def home():
    print("home")
    if flask.request.method == 'GET':
        res = redirectLoggedUsers()
        if res is not None:
            return res

        return flask.render_template('index.html', error = None)


@app.route('/code', methods=['GET', 'POST'])
def code():
    if flask.request.method == 'GET':

        res = redirectLoggedUsers(True)
        if res is not None:
            return res

        return flask.render_template('code.html', error = None)


    if 'resend_button' in flask.request.form:
        c = db.user.find({'_id': flask_login.current_user.id, "smsResend": True}).count()
        if c > 0:
            return flask.render_template('code.html', error = "SMS újraküldést egyszer lehet kérni. Kérjük lépjen velünk kapcsolatba.")
        db.user.update_one({'_id': flask_login.current_user.id}, {"$set": {"smsResend": True}}, upsert=False)

        try:
            start_verification(flask_login.current_user.phone)
        except:
            return flask.render_template('code.html', error = "Hibás telefonszám formátum, SMS nem küldhető", form=flask.request.form)

        print('SMS resend')
        return flask.render_template('code.html', error = "SMS kódjárt újraküldtük.")

    service = app.config.get(VERIFICATION_SID)

    try:
        if 'code' not in flask.request.form or flask.request.form['code'].strip() == '':
            return flask.render_template('code.html', error = "Hibás kód, próbáld újra.")

        verification_check = check_verification(flask_login.current_user.phone, flask.request.form['code'])

        if verification_check.status == "approved":
            db.user.update_one({'_id': flask_login.current_user.id}, {"$set": {"approved": True}}, upsert=False)

            return flask.redirect(BASE_URL+'/segitek')
        else:
            return flask.render_template('code.html', error = "Hibás kód, próbáld újra.")
    except:
        traceback.print_exc()
        return flask.render_template('code.html', error = "Belső hiba történt.")

    return flask.render_template('code.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if flask.request.method == 'GET':

        res = redirectLoggedUsers()
        if res is not None:
            return res

        return flask.render_template('login.html', error = None)

    user = getUserFromDB(flask.request.form['email'])
    if user is not None and hashPassword(flask.request.form['password']) == user.hash:
        flask_login.login_user(user)
        print("Hello")
        res = redirectLoggedUsers()
        if res is not None:
            return res

        #return flask.redirect('code'))
    return flask.render_template('login.html', error = "Sikertelen belépés", form=flask.request.form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if flask.request.method == 'GET':
        res = redirectLoggedUsers()
        if res is not None:
            return res

        return flask.render_template('register.html')

    tavsegitseg = False
    if 'tavsegitseg' in flask.request.form:
        tavsegitseg = True
    print(tavsegitseg)

    if 'email' not in flask.request.form:
        return flask.render_template('register.html', error = "Email megadása kötelező", form=flask.request.form)
    email = flask.request.form['email']
    if not validate_email(email):
        return flask.render_template('register.html', error = "Email nem megfelelő formátum", form=flask.request.form)

    user = getUserFromDB(email)
    if user is not None:
        return flask.render_template('register.html', error = "Van már ilyen email fiókkal felhasználó", form=flask.request.form)

    if 'password' not in flask.request.form:
        return flask.render_template('register.html', error = "Jelszó megadása kötelező", form=flask.request.form)
    password = flask.request.form['password']
    if len(password.strip()) < 6:
        return flask.render_template('register.html', error = "A jelszónak legalább 6 karakter hosszúnak kell lennie", form=flask.request.form)

    if 'phone' not in flask.request.form:
        return flask.render_template('register.html', error = "Telefonszám megadása kötelező", form=flask.request.form)
    phone = flask.request.form['phone']
    if len(phone.strip()) < 7:
        return flask.render_template('register.html', error = "Helytelen telefonszám", form=flask.request.form)
    if not phone.startswith("+36"):
        return flask.render_template('register.html', error = "Helytelen telefonszám", form=flask.request.form)

    if 'cities' not in flask.request.form:
        return flask.render_template('register.html', error = "Város megadása kötelező", form=flask.request.form)
    city = flask.request.form['cities']
    if len(city.strip()) < 2:
        return flask.render_template('register.html', error = "Helytelen város", form=flask.request.form)
    if 'name' not in flask.request.form:
        return flask.render_template('register.html', error = "Név megadása kötelező", form=flask.request.form)
    name = flask.request.form['name']
    if len(name.strip()) < 6:
        return flask.render_template('register.html', error = "Helytelen név, legalább 6 karakternek kell lennie", form=flask.request.form)



    helpTypes = flask.request.form.getlist('helpTypes')
    if len(helpTypes) == 0:
        return flask.render_template('register.html', error = "Segítség jellege nem lett kiválasztva", form=flask.request.form)

    try:
        start_verification(phone)
    except:
        return flask.render_template('register.html', error = "Hibás telefonszám formátum, SMS nem küldhető", form=flask.request.form)


    db.user.insert({'_id': email, 'hash': hashPassword(password), 'name': name, 'phone': phone, 'city': city, 'helpTypes': helpTypes, 'approved': False, 'tavsegitseg': tavsegitseg})



    user = getUserFromDB(email)
    flask_login.login_user(user)

    return flask.redirect(BASE_URL+'/code')


@app.route('/editprofile', methods=['GET', 'POST'])
@flask_login.login_required
def editprofile():
    if flask.request.method == 'GET':
        userModel = flask_login.current_user.model

        form = {}
        form['email'] = flask_login.current_user.id
        form['cities'] = flask_login.current_user.city
        form['name'] = flask_login.current_user.name
        form['tavsegitseg'] = userModel['tavsegitseg']
        form['helpTypesList'] = userModel['helpTypes']
        return flask.render_template('editprofile.html', form=form)

    tavsegitseg = False
    if 'tavsegitseg' in flask.request.form:
        tavsegitseg = True
    print(tavsegitseg)

    if 'email' not in flask.request.form:
        return flask.render_template('editprofile.html', error = "Email megadása kötelező", form=flask.request.form)
    email = flask.request.form['email']
    if not validate_email(email):
        return flask.render_template('editprofile.html', error = "Email nem megfelelő formátum", form=flask.request.form)

    if 'cities' not in flask.request.form:
        return flask.render_template('editprofile.html', error = "Város megadása kötelező", form=flask.request.form)
    city = flask.request.form['cities']
    if len(city.strip()) < 2:
        return flask.render_template('editprofile.html', error = "Helytelen város", form=flask.request.form)
    if 'name' not in flask.request.form:
        return flask.render_template('editprofile.html', error = "Név megadása kötelező", form=flask.request.form)
    name = flask.request.form['name']
    if len(name.strip()) < 6:
        return flask.render_template('editprofile.html', error = "Helytelen név, legalább 6 karakternek kell lennie", form=flask.request.form)



    helpTypes = flask.request.form.getlist('helpTypes')
    if len(helpTypes) == 0:
        return flask.render_template('editprofile.html', error = "Segítség jellege nem lett kiválasztva", form=flask.request.form)

    db.user.update_one({"_id": email}, {'$set': {'name': name, 'city': city, 'helpTypes': helpTypes, 'tavsegitseg': tavsegitseg}}, upsert = False)


    user = getUserFromDB(email)
    flask_login.login_user(user)

    return flask.redirect(BASE_URL+'/code')



@app.route('/logout')
def logout():
    flask_login.logout_user()
    return flask.redirect(BASE_URL+'/login')


@login_manager.unauthorized_handler
def unauthorized_handler():
    return flask.redirect(BASE_URL+'/login')


# ******************************************************************************
# SEGITEK
# ******************************************************************************


@app.route('/koszonjuk')
@flask_login.login_required
def koszonjuk():
    return flask.render_template('koszonjuk.html', user = flask_login.current_user.id)

@app.route('/segitek', methods=['GET'])
@flask_login.login_required
def segitek():
    return flask.render_template('segitek.html', user = flask_login.current_user.id)


@cache.cached(timeout=600)
@app.route('/rest/helpTypes')
def restHelps():
    result = []
    for c in db.helpType.find():
        result.append({"_id": str(c["_id"]), "name": c["name"]})
    return flask.jsonify(result);


@cache.cached(timeout=600)
@app.route('/rest/helpTypesOnkentes')
def restHelpsOnkentes():
    result = []
    for c in db.helpType.find({"type": {"$in": ["onkentes"]}}):
        result.append({"_id": str(c["_id"]), "name": c["name"]})
    return flask.jsonify(result);

def getHelpTypesTavsegitsegForUser():
    list = []
    osszesTavsegitseg = getHelpTypesTavsegitseg()
    for e in flask_login.current_user.helpTypes:
        if e in osszesTavsegitseg:
            list.append(e)
    return list

@app.route('/rest/segitsegKereses')
def restSegitsegKereses():

    lockedTimeout=datetime.now() - timedelta(minutes=10)

    if flask_login.current_user.tavsegitseg:
        subQuery = {"$or": [{"city": flask_login.current_user.city},{"helpType": {"$in": getHelpTypesTavsegitsegForUser()}}]}
    else:
        subQuery = {"city": flask_login.current_user.city}

    res = list(db.help.aggregate([
        {"$match": {"$and": [
        subQuery,
        {"helpType": {"$in": flask_login.current_user.helpTypes}},
        {"resolved": {"$exists": False}},
        {"$or": [{"lockedTime": {"$exists": False}}, {"lockedTime": {"$lte": lockedTimeout}}, {"lockedUser": { "$exists": False}}, {"lockedUser": flask_login.current_user.id}]},
        {"checkedByUser": {"$nin": [flask_login.current_user.id]}}]}},
    {'$group': {'_id': '$helpType', 'count': { '$sum': 1 } } } ]))

    result = []
    names = getHelpTypeNamesAll()
    for e in res:
        result.append({'helpType': str(e['_id']), 'count': str(e['count']), 'name': names[e['_id']]})

    #result = {"count": result_count}
    return flask.jsonify(result);


@app.route('/rest/mutasdASzamot')
def restMutasdASzamot():
    helpType = flask.request.args.get("helpType")
    print("HelpType: " + helpType);

    #TODO: kell majd locking ide
    #db.user.find({""}segitsegKellQuery(flask_login.current_user.city, helpType)).sort([("created", 1)]).limit(1)

    lockedTimeout=datetime.now() - timedelta(minutes=10)

    if flask_login.current_user.tavsegitseg:
        subQuery = {"$or": [{"city": flask_login.current_user.city},{"helpType": {"$in": getHelpTypesTavsegitsegForUser()}}]}
    else:
        subQuery = {"city": flask_login.current_user.city}

    segitsegKellQuery = {"$and": [
        subQuery,
        {"helpType": ObjectId(helpType)},
        {"resolved": {"$exists": False}},
        {"checkedByUser": {"$nin": [flask_login.current_user.id]}},
        {"$or": [{"lockedTime": {"$exists": False}}, {"lockedTime": {"$lte": lockedTimeout}}, {"lockedUser": { "$exists": False}}, {"lockedUser": flask_login.current_user.id}]}]}

    result = db.help.find(segitsegKellQuery).sort([("created", 1)]).limit(1)
    print(str(result.count(True)))
    if (result.count(True) != 1):
        flask.abort(404, description="Nincs már szám")

    db.help.update_one({'_id': result[0]["_id"]}, {"$set": {"lockedUser": flask_login.current_user.id, "lockedTime":datetime.now()}}, upsert=False)
    db.user.update_one({'_id': flask_login.current_user.id}, {"$set": {"helpId": result[0]["_id"]}}, upsert=False)

    result = {"id": str(result[0]["_id"]), "phone": result[0]["phone"]}
    return flask.jsonify(result);


@app.route('/rest/telefononFelhivtam')
def restTelefononFelhivtam():
    phoneUserId = flask.request.args.get("id")
    phoneResult = flask.request.args.get("result")

    if phoneUserId is None or not ObjectId.is_valid(phoneUserId):
        return ""

    print(phoneUserId)
    print(phoneResult)
    if phoneResult == "nemKellek":
        db.help.update_one({'_id': ObjectId(phoneUserId)}, {"$push": {"checkedByUser": flask_login.current_user.id}}, False)
        db.help.update_one({'_id': ObjectId(phoneUserId)}, {"$unset": {"lockedTime": "", "lockedUser": ""}}, False)
    if phoneResult == "kellek":
        db.user.update_one({'_id': flask_login.current_user.id}, {"$push": {"helped": ObjectId(phoneUserId)}}, False)
        db.help.update_one({'_id': ObjectId(phoneUserId)}, {"$set": {"resolved": phoneResult, "resolvedUser": flask_login.current_user.id}, "$unset": {"lockedTime": "", "lockedUser": ""}}, upsert=False)
    if phoneResult == "targytalan":
        db.user.update_one({'_id': flask_login.current_user.id}, {"$push": {"invalid": ObjectId(phoneUserId)}}, False)
        db.help.update_one({'_id': ObjectId(phoneUserId)}, {"$set": {"resolved": phoneResult, "resolvedUser": flask_login.current_user.id}, "$unset": {"lockedTime": "", "lockedUser": ""}}, upsert=False)

    db.user.update_one({'_id': flask_login.current_user.id}, {"$unset": {"helpId": ""}, "$set": {"helpedDate": datetime.now()}}, upsert=False)

    return ""



# ******************************************************************************
# SEGITSETEK
# ******************************************************************************
@app.route('/segitsetek', methods=['GET', 'POST'])
def segitsetek():
    if flask.request.method == 'GET':
        return flask.render_template('segitsetek.html')

    helpTypes = flask.request.form["helpTypes"]
    cities = flask.request.form["cities"]

    phone = None
    helpTypeModel = getHelpType(ObjectId(helpTypes))
    if helpTypeModel['type'] == 'onkentes':
        if 'phone' in flask.request.form:
            phone = flask.request.form["phone"]
        if phone is None or phone.strip() == "":
            return flask.render_template('segitsetek.html', error = "Telefonszám megadása kötelező", form = flask.request.form)

    city = getCity(cities)
    isTavsegitseg = helpTypeModel.get('tavsegitseg')
    helpType = getHelpType(ObjectId(helpTypes))
    
    if helpTypeModel['type'] == 'onkentes':
        db.help.insert({'phone': phone, 'helpType': ObjectId(helpTypes), 'city': cities, 'created': datetime.now()})

        if isTavsegitseg:
            res = list(db.user.find({"helpTypes": helpTypes, "tavsegitseg": True}))
        else:
            res = list(db.user.find({"city": cities, "helpTypes": helpTypes}))
        
        for e in res:
            response = sendEmail(str(e['_id']), helpType['name'])
            print("Email status: " + response.status_code)
    else:
        db.helpOnkorm.insert({'phone': phone, 'helpType': ObjectId(helpTypes), 'city': cities, 'created': datetime.now()})

    return flask.render_template('segitseg-folyamatban.html', helpType = helpTypeModel, city = city)


@app.route('/onkormanyzat', methods=['GET'])
def onkormanyzat():
    res = {}
    if 'city' in flask.request.args:
        city = getCity(flask.request.args["city"])

        if city is not None:
            res['telefon'] = city['telefon']
            res['email'] = city['email']
            res['link'] = city['link']

            db.helpOnkormGPS.insert({'city': flask.request.args["city"], 'created': datetime.now()})

    return flask.jsonify(res);


# ******************************************************************************
# static
# ******************************************************************************
@cache.cached(timeout=600)
@app.route('/adatkezeles', methods=['GET', 'POST'])
def adetkezeles():
    return flask.render_template('adatkezeles.html')

@cache.cached(timeout=600)
@app.route('/aszf', methods=['GET', 'POST'])
def aszf():
    return flask.render_template('aszf.html')

@app.route('/kapcsolat', methods=['GET', 'POST'])
def kapcsolat():
    if flask.request.method == 'GET':
        return flask.render_template('kapcsolat.html')

    phone = None
    if 'phone' in flask.request.form:
        phone = flask.request.form["phone"]
    if phone is None or phone.strip() == "":
        return flask.render_template('kapcsolat.html', error = "Telefonszám megadása kötelező", form = flask.request.form)

    name = None
    if 'name' in flask.request.form:
        name = flask.request.form["name"]
    if name is None or name.strip() == "":
        return flask.render_template('kapcsolat.html', error = "Név megadása kötelező", form = flask.request.form)

    text = None
    if 'text' in flask.request.form:
        text = flask.request.form["text"]
    if text is None or text.strip() == "":
        return flask.render_template('kapcsolat.html', error = "Leírás megadása kötelező", form = flask.request.form)

    email = None
    if 'email' in flask.request.form:
        email = flask.request.form["email"]
    if email is None or email.strip() == "":
        return flask.render_template('kapcsolat.html', error = "Email megadása kötelező", form = flask.request.form)

    type = None
    if 'type' in flask.request.form:
        type = flask.request.form["type"]
    if type is None or type.strip() == "":
        return flask.render_template('kapcsolat.html', error = "Típus megadása kötelező", form = flask.request.form)

    db.contact.insert({'phone': phone, 'type': type, 'email': email, 'text': text, 'name': name})

    return flask.render_template('kapcsolat.html', form = flask.request.form, success= True)


# ******************************************************************************
# SEGITSETEK
# ******************************************************************************

if __name__ == '__main__':
    from waitress import serve
    serve(app, host="0.0.0.0", port=5001)
    #app.run()
