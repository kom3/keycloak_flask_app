import json
import logging

from flask import Flask, g, redirect
from flask_oidc import OpenIDConnect
import requests

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'myrealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc = OpenIDConnect(app)


@app.route('/')
#@oidc.require_login
def hello_world():
    if oidc.user_loggedin:
        oidc.logout()
        return redirect("http://127.0.0.1:5000/private", code=302)
    else:
        return redirect("http://127.0.0.1:5000/private", code=302)
@app.route('/private')
@oidc.require_login
def hello_me():
    """Example for protected endpoint that extracts private information from the OpenID Connect id_token.
       Uses the accompanied access_token to access a backend service.
    """

    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])

    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')

    if user_id in oidc.credentials_store:
        try:
            from oauth2client.client import OAuth2Credentials
            access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
            print('access_token=<%s>' % access_token)
            headers = {'Authorization': 'Bearer %s' % (access_token)}
            # YOLO
            greeting = requests.get('http://localhost:8080/greeting', headers=headers).text
        except:
            print("Could not access greeting-service")
            greeting = "Hello %s" % username

    else:
        greeting=""
    

    return ("""<head><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css"></head><div style="border-top: 27px double #f7f7f7; border-bottom: 27px double #f7f7f7; padding: 5px; height: 300px; background-color: lavender; border-radius: 77px;">
            <div style="text-align:center; color:green; font-size:22px;">Available Apps</div>
               <div  style="display: flex; padding: 45px; text-align:center">
                 <div><a href="http://127.0.0.1:8000/"><i style="font-size: 96px; border: 7px solid #e6e6fa;; padding: 10px; background-color: #1e1e1d; border-radius: 34px; color:red" class="fa fa-fighter-jet" aria-hidden="true"></i><br>KATANA
</a></div>
                </div>
            </div>""")


@app.route('/api', methods=['POST'])
@oidc.accept_token(require_token=True, scopes_required=['openid'])
def hello_api():
    """OAuth 2.0 protected API endpoint accessible via AccessToken"""

    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['sub']})


@app.route('/refresh')
def refresh():
    """Performs local logout by removing the session cookie."""
    oidc.logout()
    return redirect("http://127.0.0.1:5000/", code=302)


if __name__ == '__main__':
    app.run()
