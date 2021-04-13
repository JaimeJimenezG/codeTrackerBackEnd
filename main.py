from flask import Flask, request, jsonify, Response, request, session
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson import json_util, objectid
from flask_cors import CORS
import jwt
import datetime
from functools import wraps
import os
import json

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
CORS(app)
app.config['SECRET_KEY']='248593782395729384327589320'
app.config['MONGO_URI']="mongodb://localhost/codetracker"

mongo = PyMongo(app)
os.system("service code-server@jaime start") # woke up service code-server
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
    ownersId = request.json["ownersId"]
    path = request.json["path"]
    desc = request.json["desc"]
    workspace = request.json["workspace"]
    procesName = request.json["procesName"]
    startCommand = request.json["startCommand"]
    stopCommand = request.json["stopCommand"]
    createWorkspace(path, workspace)
    if name and ownersId and path and desc and workspace and procesName and startCommand and stopCommand:
        id = mongo.db.projects.insert(
            {  
                "name": name,
                "ownersId": ownersId,
                "path": path,
                "desc": desc,
                "procesName": procesName,
                "workspace": workspace,
                "startCommand": startCommand,
                "stopCommand": stopCommand
            }
        )
        response = {
            "id": str(id),
            "name": name,
            "ownersId": ownersId,
            "path": path,
            "desc": desc,
            "procesName": procesName,
            "workspace": workspace,
            "startCommand": startCommand,
            "stopCommand": stopCommand
        }
        return response
    else:
        return notFound()
def createWorkspace(path, workspaceName):
    workspace = {
        "folders": [
            {
                "path": path
            }
        ],
        "remoteAuthority": "192.168.1.22:8080",
	    "settings": {}
    }
    print(workspaceName)
    with open('/home/jaime/.local/share/code-server/User/Workspaces/'+str(workspaceName)+'.code-workspace', 'w') as outfile:
        json.dump(workspace, outfile)
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
    mongo.db.projects.delete_one({"_id": objectid.ObjectId(id)})
    response = jsonify({"response": "Project"+ id +" was deleated successfully."})
    return response
@app.route("/project/GetStates/", methods=["GET"])
def getStatesOfProject():
    os.system("./sysinfo.sh")
    with open("../data/top.txt", 'r') as read_obj:         
        response = {}
        for line in read_obj:
            line = line.replace("/","")
            line = line.split();
            createObject = {}
            createObject["process"] = line[0]
            createObject["memoryUsage"] = line[1]
            createObject["cpuUsage"] = line[2]
            response[line[0]] = createObject
    return {"response": response }
@app.route("/project/start", methods=["POST"])
def procesStart():
    print(request.json)
    command = request.json['command']
    os.system(command)
    return { " response": "started" }
@app.route("/project/stop", methods=["POST"])
def procesStop():
    command = request.json['command']
    os.system(command)
    return { " response": "stopped" }
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

app.run(host="192.168.1.22", debug=True)

#Lenguajes

#if __name__ == "__main__":
    