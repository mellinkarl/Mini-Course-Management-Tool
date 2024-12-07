# Mini-Course-Management-Tool

## Overview
This tool is created as a practice for developing something like Canvas.

Currently, there are 9 users in Auth0:
admin1@osu.com
instructor1@osu.com, instructor2@osu.com
student1@osu.com, student2@osu.com, ... , student6@osu.com.

As of now, Postman or another HTTP request software must be used with valid credentials (as specified in  dataDescription.pdf) to send requests to the application.


## Technology Stack:

This application is mainly built in python for now, using a virtual environment to test locally.
     
### 1. Google Cloud Platform:
   - Cloud Datastore API: For storing information about users and courses.
   - Cloud Logging API: For debugging purposes.
   - Cloud Firestore API: For caching and querying of data.
   - Cloud Storage Buckets: For storing user avatars.

### 2. Flask:
   - Routing: Defines various endpoints (routes) for handling HTTP requests.
         - For example: POST /users/login route.
   - Request Handling: Retrieves request headers, bodies, and parameters (JSON payloads, query strings) and handles file uploads for user avatars.
   - Response Handling: Sends HTTP responses with appropriate status codes and payloads.
         - For example: (course, 201) in the POST /courses route.
   - Error Handling: Provides custom error handlers for responding to authentication or data validation errors.
   - Integration with Services:
         - Auth0 for user authentication.
         - Google Cloud Datastore for managing data.
         - Google Cloud Storage for managing user avatars.

### 3. Auth0:
   - Used for JWT authorization scheme in validating users.
   - 9 pre-created users.

### 4. Postman:
   - Primary use of testing each endpoint and the data/user validation they should have.
   - Use of test scripts for verifying HTTP responses.

### Next Steps:
The next step for this project are to implement a front-end interface for the application. After the UI is completed, I plan to make the userbase scalable (cost permitting).
