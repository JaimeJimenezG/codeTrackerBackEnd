from flask import Flask, request, jsonify, Response, url_for, request, session, redirect, make_response
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import json_util, objectid
from flask_cors import CORS
import uuid
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import os

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
CORS(app)
app.config['SECRET_KEY']='248593782395729384327589320'
app.config['MONGO_URI']="mongodb://localhost/codetracker"

mongo = PyMongo(app)

# Routes

#Login
@app.route('/login/signin', methods=['POST'])
def login():
    json_data = request.json
    user = mongo.db.users.find_one({"username": json_data["username"]})
    userId = str(user["_id"])
    if user and check_password_hash(
        user["password"], json_data['password']):
        token = jwt.encode({'_id': userId, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        print(token)
        return jsonify({
            "id": userId,
            "username": user["username"],
            "email": user["email"],
            "nombre": user["nombre"],
            "apellido": user["apellido"],
            'accessToken' : token,
            "response": True
            }) 
    else:
        status = False
        return jsonify({
            'response': status})

@app.route('/api/logout')
def logout():
    session.pop('logged_in', None)
    return jsonify({'response': 'success'})
#Users
@app.route("/users", methods=["POST"])
def createUser():
    #Recive
    username = request.json["username"]
    password = request.json["password"]
    email = request.json["email"]
    nombre = request.json["nombre"]
    apellido = request.json["apellido"]
    if nombre and password and username and email and apellido:
        hashed_password = generate_password_hash(password)
        id = mongo.db.users.insert(
            {
                "username": username,
                "email": email,
                "password": hashed_password,
                "nombre": nombre,
                "apellido": apellido
            }
        )
        response = {
            "id": str(id),
            "username": username,
            "password": hashed_password,
            "email": email,
            "nombre": nombre,
            "apellido": apellido
        }
        return response
    else:
        return notFound()
@app.route("/users/<id>", methods=["GET"])
def getUser(id):
    user = mongo.db.users.find_one({"_id": objectid.ObjectId(id)})
    response = json_util.dumps(user)
    return Response(response, mimetype="application/json")
@app.route("/users/<id>", methods=["DELETE"])
def deleteUser(id):
    mongo.db.users.delete_one({"_id": objectid.ObjectId(id)})
    response = jsonify({"response": "User"+ id +"was deleated successfully."})
    return response
@app.route("/users/<id>", methods=["PUT"])
def updateUser(id):
    username = request.json["username"]
    password = request.json["password"]
    email = request.json["email"]
    nombre = request.json["nombre"]
    apellido = request.json["apellido"]
    if nombre and password and username and email and apellido:
        hashed_password = generate_password_hash(password)
        mongo.db.users.update_one({"_id": objectid.ObjectId(id)}, {"$set": {
            "username": username,
            "password": hashed_password,
            "email": email,
            "nombre": nombre,
            "apellido": apellido
        }})
        response = jsonify({"response": "User"+ id +"was updated successfully."})
        return response
@app.errorhandler(404)
def notFound(error=None):
    response = jsonify({
        "response": "resource not found: " + request.url,
        "status": 404
    })
    response.status_code = 404
    return response

#Proyectos
@app.route("/projects", methods=["POST"])
def createProject():
    name = request.json["name"]
    languajes = request.json["languajes"]
    ownersId = request.json["ownersId"]
    path = request.json["path"]
    ownersNames = request.json["ownersNames"]
    desc = request.json["desc"]
    if name and languajes and ownersId and path and ownersNames and desc:
        id = mongo.db.projects.insert(
            {  
                "name": name,
                "languajes": languajes,
                "ownersId": ownersId,
                "path": path,
                "ownersNames": ownersNames,
                "desc": desc
            }
        )
        response = {
            "id": str(id),
            "name": name,
            "languajes": languajes,
            "ownersId": ownersId,
            "path": path,
            "ownersNames": ownersNames,
            "desc": desc
        }
        return response
    else:
        return notFound()
@app.route("/projects/<userId>", methods=["GET"])
def getProjectsByUserId(userId):
    projects = mongo.db.projects.find({"ownersId": userId})
    print(userId)
    response = json_util.dumps(projects)
    print(response)
    return Response(response, mimetype="application/json")
@app.route("/project/<id>", methods=["GET"])
def getProject(id):
    project = mongo.db.projects.find_one({"_id": objectid.ObjectId(id)});
    response = json_util.dumps(project)
    return Response(response, mimetype="application/json")
@app.route("/project/<id>", methods=["DELETE"])
def deleteProject(id):
    mongo.db.project.delete_one({"_id": objectid.ObjectId(id)})
    response = jsonify({"response": "Project"+ id +"was deleated successfully."})
    return response
@app.route("/project/GetStates/<procesName>", methods=["GET"])
def getStatesOfProject(procesName):
    #os.system("top -b -n 1 > ../../data/top.txt") #unncommeht when ported to linux base server
    with open("../../data/top.txt", 'r') as read_obj:
        for line in read_obj:
            print(line)
            if procesName in line:
                response = {}
                line = line.split();
                response["pid"] = line[0]
                response["user"] = line[1]
                response["pr"] = line[2]
                response["ni"] = line[3]
                response["virt"] = line[4]
                response["res"] = line[5]
                response["shr"] = line[6]
                response["s"] = line[7]
                response["cpu%"] = line[8]
                response["ram%"] = line[9]
                response["time"] = line[10]
                response["proccesName"] = line[11]
                return {"response": response }
                
    return {"response": False }




#Token
def token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-tokens' in request.headers:
         token = request.headers['x-access-tokens']

      if not token:
         return jsonify({'message': 'a valid token is missing'})

      try:
         data = jwt.decode(token, app.config["SECRET_KEY"])
         current_user =mongo.db.users.find_one({"username": data['public_id']})
         
      except:
         return jsonify({'message': 'token is invalid'})
   return decorator

app.run(host="127.0.0.1", debug=True)

#Lenguajes

#if __name__ == "__main__":
    