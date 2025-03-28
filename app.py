
from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
import pandas as pd
from tensorflow.keras.models import load_model
app = Flask(__name__)
import numpy as np
import re

from urllib.parse import urlparse

model = load_model("CNN1D_BiLSTM.h5")

cors = CORS(app, resources={r"/*": {"origins": "*"}})

@app.route("/", methods=['GET'])
def index():
    return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>URL Predictor</title>
            <script>
                function sendPrediction() {
                    var urlInput = document.getElementById("url").value;
                    fetch("/predict", {
                        method: "POST",
                        headers: {
                            "Content-Type": "application/json"
                        },
                        body: JSON.stringify({ "url": urlInput })
                    })
                    .then(response => response.json())
                    .then(data => {
                        document.getElementById("result").innerText = "Prediction: " + data.prediction;
                    })
                    .catch(error => {
                        document.getElementById("result").innerText = "Error: " + error;
                    });
                }
            </script>
        </head>
        <body>
            <h1>Enter a URL to Predict</h1>
            <input type="text" id="url" placeholder="Enter URL here">
            <button onclick="sendPrediction()">Submit</button>
            <p id="result"></p>
        </body>
        </html>
    '''

@app.route('/predict', methods=['POST'])
@cross_origin()
def predict():
    
    data = request.get_json()
    url = data.get("url")
    print("URL: " + url)
    
    transform_url = transformURL(url)

    transform_url = transform_url.reshape(1, -1)

    # print("transform_url" , transform_url)
    feature_names = ['use_of_ip','abnormal_url', 'count.', 'count-www', 'count@',
       'count_dir', 'count_embed_domain', 'short_url', 'count%', 'count?', 'count-', 'count=', 'url_length', 'count_https',
       'count_http', 'hostname_length', 'sus_url', 'fd_length', 'tld_length', 'count_digits',
       'count_letters']
    transform_url = pd.DataFrame(transform_url, columns=feature_names)
    prediction = model.predict(transform_url)
    print(prediction)
  
    class_labels = ["benign", "defacement", "phishing", "malware"]
    predicted_index = np.argmax(prediction, axis=1)[0]
    predicted_label = class_labels[predicted_index]
    print(predicted_label)
    response = jsonify({'prediction': predicted_label})

    return response


def transformURL(url):
        try:
            use_of_ip = having_ip_address(url)
            abnormal_url = abnormalURL(url)
            countDot = count_Dot(url)
            countWWW = count_Www(url)
            countATR = count_Atrate(url)
            count_dir= no_of_Dir(url)
            count_embed_domain = no_of_Embed(url)
            short_url = shortening_Service(url)
            countPercentage = count_Per(url)
            countQUES = count_Ques(url)
            countHyphen = count_Hyphen(url)

            countEqual = count_Equal(url)
            url_length = url_Length(url)
            count_https = count_Https(url)
            count_http = count_Http(url)
            hostname_length = hostname_Length(url)
            sus_url = suspicious_Words(url)
            fd_length = fd_Length(url)
            tld_length = tld_Length(url)
            count_digits = digit_Count(url)
            count_letters = letter_Count(url)

            ls = [use_of_ip,abnormal_url,countDot, countWWW,countATR,count_dir,count_embed_domain,short_url,countPercentage,countQUES,countHyphen,countEqual,url_length,count_https ,count_http,
                  hostname_length,sus_url,fd_length,tld_length,count_digits,count_letters]

            arr = np.array(ls)

            return arr
        
        except Exception as e:
            print(e)

def having_ip_address(url):
        try:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
            if match:
                return 1
            else:
                return 0
            
        except Exception as e:
            print(e)
        
def abnormalURL(url):
    try:
        hostname = urlparse(url).hostname
        hostname = str(hostname)
        match = re.search(hostname, url)
        if match:      
            return 1
        else:
            return 0

    except Exception as e:
        print(e)
    

def count_Dot(url):
    try:
        count_dot = url.count('.')
        return count_dot

    except Exception as e:
        print(e)
    

def count_Www(url):
    try:
        url.count('www')
        return url.count('www')
    except Exception as e:
        print(e)
    

def count_Atrate(url):
    try:
        return url.count('@')
    except Exception as e:
        print(e)
    

def no_of_Dir(url):
    try:
        urldir = urlparse(url).path
        return urldir.count('/')
    except Exception as e:
        print(e)
    

def no_of_Embed(url):
    try:
        urldir = urlparse(url).path
        return urldir.count('//')
    except Exception as e:
       print(e)
    

def suspicious_Words(url):
    try:
        match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                        url)
        if match:
            return 1
        else:
            return 0
    except Exception as e:
        print(e)
    

def shortening_Service(url):
    try:
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net',
                        url)
        if match:
            return 1
        else:
            return 0
    except Exception as e:
        print(e)
    

def count_Https(url):
    try:
        return url.count('https')
    except Exception as e:
        print(e)
    

def count_Http(url):
    try:
        return url.count('http')
    except Exception as e:
        print(e)
    

def count_Per(url):
    try:
        return url.count('%')
    except Exception as e:
        print(e)
    

def count_Ques(url):
    try:
        return url.count('?')
    except Exception as e:
        print(e)
    

def count_Hyphen(url):
    try:
        return url.count('-')
    except Exception as e:
        print(e)
    

def count_Equal(url):
    try:
        return url.count('=')
    except Exception as e:
        print(e)
    

def url_Length(url):
    try:
        return len(str(url))
    except Exception as e:
        print(e)
    

def hostname_Length(url):
    try:
        return len(urlparse(url).netloc)
    except Exception as e:
        print(e)
    

def fd_Length(url):
    try:
        urlpath= urlparse(url).path
        try:
            return len(urlpath.split('/')[1])
        except:
            return 0
    except Exception as e:
        print(e)
    

def tld_Length(tld):
    try:
        try:
            return len(tld)
        except:
            return -1
    except Exception as e:
        print(e)
    

def digit_Count(url):
    try:
        digits = 0
        for i in url:
            if i.isnumeric():
                digits += 1
        return digits
    except Exception as e:
        print(e)
    

def letter_Count(url):
    try:
        letters = 0
        for i in url:
            if i.isalpha():
                letters += 1
        return letters
    except Exception as e:
        print(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
