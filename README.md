# source-alpha
Alpha source code, from November 3rd, 2023 (last alpha version I could find), patched with "new" stylesheet from November 11st. Email and captcha verification is disabled, but you can easily active it from the source code.


## Features
- Login/Register
- Profile Page
- Follow/Unfollow
- Following timeline, Public timeline and Top 10 Most Favorited
- Settings are partially working, some features were WIP
![sample](https://github.com/owlir/source-alpha/blob/main/samples/1.png)

## Contributions

The source is old, but if you want to contribuite and make a pull request, you're free to do so.

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
The source code is licensed under the BSD license.
