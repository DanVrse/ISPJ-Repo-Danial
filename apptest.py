from flask import Flask, render_template, abort, send_file

# file upload
from werkzeug.utils import secure_filename
import os
#import magic
import urllib.request
from datetime import datetime


app = Flask(__name__)

UPLOAD_FOLDER = 'C:/ISPJ uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024


@app.route('/', defaults={'req_path': ''})
@app.route('/<path:req_path>')
def dir_listing(req_path):
    BASE_DIR = 'C:/ISPJ uploads'

    # Joining the base and the requested path
    abs_path = os.path.join(BASE_DIR, req_path)

    # Return 404 if path doesn't exist
    if not os.path.exists(abs_path):
        return abort(404)

    # Check if path is a file and serve
    if os.path.isfile(abs_path):
        return send_file(abs_path)

    # Show directory contents
    files = os.listdir(abs_path)
    return render_template('test.html', files=files)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
