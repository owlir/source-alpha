# source-alpha
Alpha source code, from November 2023

## Install
Python 3.9> is required.

### Steps
- A mongoDB server is required, you can install it here: https://www.mongodb.com/try/download/community
- Create a pyvenv;
- Install the requirements.txt using `pip install -r requirements.txt`
- Start a development server using `flask --app api.index:app run`

## Deploy

If you are smart, there's places you can host this app for free (Google App Engine, AWS Lambda, Vercel, Render) with MongoDB Atlas. At the time, the source was optimized for Vercel, but it's not the best place for hosting Python websites

~After I rewrote the code and with a greater number of active users, it became unfeasible to use these options :')~

If you are going to host manually, I recommend following instructions on how to host a Flask app - https://www.digitalocean.com/community/tutorials/how-to-serve-flask-applications-with-gunicorn-and-nginx-on-ubuntu-22-04
 
## License
The source code is licensed under the BSD license. Respect the integrity of the license and use the source code respectfully.
