from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage
import io
import requests
import json
from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()


# Update the values of the following 3 variables
CLIENT_ID = '1cFOTTj3VF29qoPMHLYrrHLKAzfrKGtr'
CLIENT_SECRET = 'IdZ8w-tt5CcJ8ZUv1DBN74BOWgSUouVfTUSR_QiAgDzdI-smcQrDrnufzc8lWX9U'
DOMAIN = 'cs493-hw6-mellinka.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

PHOTO_BUCKET = "hw6-mellinka-bucket"

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /users/login to use this API"\

# ----------------------------------------------------------- #
#                       User Routes                           #
# ----------------------------------------------------------- #

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/users/login', methods=['POST'])
def login_user():

    # Check for username and password in request
    content = request.get_json()
    if 'username' not in content or 'password' not in content:
        return {"Error": "The request body is invalid"}, 400
    
    username = content["username"]
    password = content["password"]
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code == 403:
        return {"Error": "Unauthorized"}, 401
    token = r.json().get('id_token')
    return {'token': token}, 200, {'Content-Type':'application/json'}


# Get all users
# Request must come with the JWT of a user with the 'admin' role
@app.route('/users', methods=['GET'])
def get_all_users():

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code

    # Ensure request is made with JWT of admin
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin":
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Retrieve all users from Datastore, add id field and send back
    users = list((client.query(kind="users")).fetch())
    for user in users:
        user['id'] = user.key.id
    return (users, 200)
 
 
# Get a single user
# Request must be sent with admin JWT or JWT of user that is being requested
@app.route('/users/<int:id>', methods=['GET'])
def get_user(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code

    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())

    # If user doesn't exist return 403
    if not results[0]:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # If JWT doesn't correspond to admin or the user whose ID is in path parameter return 403
    user = results[0]
    if (user.key.id != id) and (user['role'] != 'admin'):
        return {"Error": "You don't have permission on this resource"}, 403

    # Query Google Cloud Storage for avatar
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    file_name = str(id) + '.png'
    blob = bucket.blob(file_name)

    # See if user has an avatar, if so update user return
    if blob.exists():
        user['avatar_url'] = request.host_url + 'users/' + str(id) + '/avatar'

    # If user is instructor, create 'courses' field with links of all courses they teach
    if user['role'] == 'instructor':
        course_query = client.query(kind='courses')
        course_query.add_filter('instructor_id', '=', id)
        courses = list(course_query.fetch())
        course_urls = []
        for course in courses:
            course_url = request.host_url + 'courses/' + str(course.key.id)
            course_urls.append(course_url)
        user['courses'] = course_urls

    # If user is student, create 'courses' field with links of all courses they are enrolled in
    elif user['role'] == 'student':
        course_query = client.query(kind='courses')
        courses = list(course_query.fetch())
        student_courses = []
        for course in courses:
            if 'Enrollment' in course and id in course['Enrollment']:
                course_url = request.host_url + 'courses/' + str(course.key.id)
                student_courses.append(course_url)
        user['courses'] = student_courses

    user['id'] = id
    return (user, 200)


# Create/update a user's avatar
@app.route('/users/<int:id>/avatar', methods=['POST'])
def create_user_avatar(id):

    # Return 400 if there is no file in the request
    if 'file' not in request.files:
        return {"Error": "The request body is invalid"}, 400
    
    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())

    # If JWT doesn't correspond to the user whose ID is in path parameter return 403
    user = results[0]
    if user.key.id != id:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Get file and ensure it is read from the beginning
    file_obj = request.files['file']
    file_obj.seek(0)

    # Connect to Cloud Storage Bucket
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)

    # Store file in Cloud Storage Bucket as userID.png
    blob = bucket.blob(str(user.key.id) + '.png')
    blob.upload_from_file(file_obj)

    # Return avatar_url
    avatar_url = request.host_url + "users/" + str(id) + "/avatar"
    return ({'avatar_url' : avatar_url}, 200)
    

# Get a user's avatar
# JWT must be owned by id in path parameter
@app.route('/users/<int:id>/avatar', methods=['GET'])
def get_user_avatar(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())

    # If JWT doesn't correspond to the user whose ID is in path parameter return 403
    user = results[0]
    user_id = user.key.id
    if user_id != id:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Query Cloud Storage Bucket for avatar
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    file_name = str(user_id) + '.png'
    blob = bucket.blob(file_name)

    # Ensure user's avatar exists in GCS
    # Adapted from https://stackoverflow.com/questions/13525482/how-to-check-if-file-exists-in-google-cloud-storage
    if not blob.exists():
        return {"Error": "Not found"}, 404
    
    # Download file and send to client with 200 code
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)                                                                                # Set to beginning of .png file
    return (send_file(file_obj, mimetype='image/png', download_name=file_name), 200)
    

# Delete a user's avatar
# JWT must be owned by id in path parameter
@app.route('/users/<int:id>/avatar', methods=['DELETE'])
def delete_user_avatar(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Get user from Datastore
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())

    # If JWT doesn't correspond to requested avatar with user's id return 403 
    user = results[0]
    user_id = user.key.id
    if user_id != id:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Query Cloud Storage Bucket for avatar
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)
    file_name = str(user_id) + '.png'
    blob = bucket.blob(file_name)

    # Ensure image exists in GCS
    # Adapted from https://stackoverflow.com/questions/13525482/how-to-check-if-file-exists-in-google-cloud-storage
    if not blob.exists():
        return {"Error": "Not found"}, 404
    
    blob.delete()
    return ('', 204)



# ----------------------------------------------------------- #
#                       Course Routes                         #
# ----------------------------------------------------------- #

# Create a course
@app.route('/courses', methods=['POST'])
def create_course():

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Ensure user is admin
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin":
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Ensure all fields are present in the request
    content = request.get_json()
    course_fields = ['subject', 'number', 'title', 'term', 'instructor_id']
    for field in course_fields:
        if field not in content:
            return {"Error": "The request body is invalid"}, 400
        
    # Ensure user exists and is instructor
    user_key = client.key('users', content['instructor_id'])
    user = client.get(key=user_key)
    if user['role'] != 'instructor' or not user:
        return {"Error": "The request body is invalid"}, 400
    
    course = datastore.Entity(client.key('courses'))
    course.update(content)

    # Add empty enrollment field fo course
    course.update({'Enrollment': []})
    client.put(course)

    # Add id and self field to return to user
    course['id'] = course.key.id
    course['self'] = request.host_url + 'courses/' + str(course['id'])
    del course['Enrollment']
    return (course, 201)


# Get all courses
# Paginated with page size of 3
@app.route('/courses', methods=['GET'])
def get_all_courses():
    # Get offset and limit for pagination
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 3))

    # Query Datastore for all courses
    course_query = client.query(kind='courses')
    course_query.order = ['subject']                                                            # Order by subject
    c_iterator = course_query.fetch(limit=limit, offset=offset)
    pages = c_iterator.pages
    courses = list(next(pages))
    for course in courses:
        course['id'] = course.key.id
        course['self'] = request.host_url + 'courses/' + str(course['id'])
        del course['Enrollment']                                                               # Do not send enrollment back to client

    # If < lim courses to return send back full list without 'next' link
    # Otherwise send back lim courses with 'next' link
    if len(courses) < limit:
        return ({'courses': courses}, 200)
    else:
        offset += limit
        next_url = request.host_url + 'courses?offset=' + str(offset) + '&limit=' + str(limit)

    return ({'courses': courses, 'next': next_url}, 200)
        

# Get a course's info
@app.route('/courses/<int:id>', methods=['GET'])
def get_course(id):

    # Ensure course exists
    course_key = client.key('courses', id)
    course = client.get(key=course_key)
    if not course:
        return {"Error": "Not found"}, 404
    
    course['id'] = course.key.id
    course['self'] = request.host_url + 'courses/' + str(id)
    del course['Enrollment']                                                                    # Do not send enrollment back to client
    return (course, 200)


# Update a course
# Student enrollment cannot be verified via this endpoint
# JWT must be of an admin
@app.route('/courses/<int:id>', methods=['PATCH'])
def update_course(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Ensure the user is admin
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin":
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Ensure course exists
    course_key = client.key('courses', id)
    course = client.get(key=course_key)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # If instructor_id is present, verify that user exists and has instructor role in Datastore
    content = request.get_json()
    if 'instructor_id' in content:
        user_key = client.key('users', content['instructor_id'])
        user = client.get(key=user_key)
        if not user or user['role'] != 'instructor':
            return {"Error": "The request body is invalid"}, 400
        
    # Update course in Datastore and return to client
    course.update(content)
    client.put(course)
    course['id'] = course.key.id
    course['self'] = request.host_url +'courses/' + str(course['id'])
    del course['Enrollment']                                                                        # Do not send enrollment back to client
    return (course, 200)
        

# Delete a course
# Deletes enrollment of students and instructor from that course
@app.route('/courses/<int:id>', methods=['DELETE'])
def delete_course(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Ensure the user is admin
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin":
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Ensure course exists
    course_key = client.key('courses', id)
    course = client.get(key=course_key)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Delete course from Datastore
    client.delete(course_key)
    return ('', 204)


# ----------------------------------------------------------- #
#                       Enrollment Routes                     #
# ----------------------------------------------------------- #

# Update the enrollment in a course
# JWT must be an admin's or instructor of the course
@app.route('/courses/<int:id>/students', methods=['PATCH'])
def update_course_enrollment(id):
    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Ensure course exists
    course_key = client.key('courses', id)
    course = client.get(key=course_key)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403
    enrollment = course['Enrollment']

    # Ensure the user is admin or instructor of the course
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin" and user.key.id != course['instructor_id']:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Get list of students to verify for 'add' and 'remove' lists
    student_query = client.query(kind='users')
    student_query.add_filter('role', '=', 'student')
    students = list(student_query.fetch())
    student_ids = {student.key.id for student in students}


    content = request.get_json()
    for student_id in content['add']:
        if (student_id in content['remove']) or (student_id not in student_ids):                    # 409 if duplicate id in remove or id not a student/doesn't exist
            return {"Error": "Enrollment data is invalid"}, 409
        elif student_id in enrollment:                                                              # If student already enrolled skip their id
            continue
        else:
            # Add student to enrollment
            enrollment.append(student_id)

    for student_id in content['remove']:                                                            # 409 if id not a student/doesn't exist
        if student_id not in student_ids:
            return {"Error": "Enrollment data is invalid"}, 409
        elif student_id not in enrollment:                                                          # If student already not enrolled skip their id
            continue
        else:
            # Remove student from enrollment
            enrollment.remove(student_id)

    client.put(course)
    return ('', 200)

        
# Get enrollment for a course
# JWT must be an admin's or instructor of the course
@app.route('/courses/<int:id>/students', methods=['GET'])
def get_course_enrollment(id):

    # Ensure JWT is valid
    try:
        payload = verify_jwt(request)
    except AuthError as e:
        return {"Error": "Unauthorized"}, e.status_code
    
    # Ensure course exists
    course_key = client.key('courses', id)
    course = client.get(key=course_key)
    if not course:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # Ensure the user is admin or instructor of the course
    sub = payload['sub']
    query = client.query(kind='users')
    query.add_filter('sub', '=', sub)
    results = list(query.fetch())
    user = results[0]
    if user["role"] != "admin" and user.key.id != course['instructor_id']:
        return {"Error": "You don't have permission on this resource"}, 403
    
    # course['Enrollment'] is updated as enrollment variable points to it in memory
    return (course['Enrollment'], 200)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

