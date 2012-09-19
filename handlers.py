# Copyright 2012 Google Inc. All Rights Reserved.

"""Contains RequestHandler implementations for the pages we display."""

__author__ = 'Dean Harding <deanh@google.com>'

import base64
import os
from itertools import izip, cycle
import jinja2
import json
from urllib import urlencode
import urlparse
import webapp2 as webapp

from google.appengine.api import urlfetch
from google.appengine.api import memcache


CLIENT_ID = "<CLIENT-ID>"
CLIENT_SECRET = "<CLIENT-SECRET>"
SCOPES = ["https://www.googleapis.com/auth/apps.order",
          "https://www.googleapis.com/auth/apps.order.readonly"]

OAUTH_BASE_URI = "https://accounts.google.com/o/oauth2"
API_BASE_URI = "https://www.googleapis.com/apps/reseller"

XOR_KEY = "<RANDOM_STRING>"


jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(
    os.path.join(os.path.dirname(__file__), 'tmpl')))


def xor_string(data, key):
  """Simple XOR-based 'encryption'.

  A real app would do something more secure."""
  return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))


class BaseHandler(webapp.RequestHandler):
  def _GetToken(self):
    """Gets the authentication token that represents the authenticated user.

    If the user has not authenticated yet, this will be None."""
    if "token" not in self.request.cookies:
      return None

    token = self.request.cookies["token"]
    if token == "None":
      return None

    return xor_string(base64.b64decode(token), XOR_KEY)

  def _UseSandbox(self):
    """Determines whether the user has asked us to talk to the Sandbox API
    or the real API."""
    if "use-sandbox" not in self.request.cookies:
      return False

    useSandbox = self.request.cookies["use-sandbox"]
    return useSandbox == "yes"

  def _GetApiUri(self):
    uri = API_BASE_URI
    if self._UseSandbox():
      uri += "/v1sandbox"
    else:
      uri += "/v1"
    return uri

  def _Render(self, tmplName, data):
    """Renders the given template with the given data.

    We add a few extra parameters to the data to handle the authentication
    tokens and whatnot.

    Args:
      tmplName: The name of the template to render.
      data: A dictionary of the data to pass to the template."""

    if self._GetToken():
      data["authenticated"] = True
      data["useSandbox"] = self._UseSandbox()
    else:
      redirect_uri = urlparse.urljoin(self.request.url, "/oauth2callback")
      oauth_url = (OAUTH_BASE_URI + "/auth?" +
                   "response_type=code&" +
                   "client_id=" + CLIENT_ID + "&" +
                   "redirect_uri="+redirect_uri+"&" +
                   "scope=" + "%20".join(SCOPES) + "&" +
                   "approval_prompt=force")
      data["oauth_url"] = oauth_url
      data["authenticated"] = False

    tmpl = jinja_env.get_template(tmplName)
    self.response.out.write(tmpl.render(data))


class MainHandler(BaseHandler):
  """The 'index' page when you first visit the site."""
  # Method needs to be 'get()' since that's what webapp requires.
  # pylint: disable=C6409

  def get(self):
    self._Render("index.html", {})


class OpListSubscriptions(BaseHandler):
  # Method needs to be 'get()' since that's what webapp requires.
  # pylint: disable=C6409
  def get(self):
    data = {}
    token = self._GetToken()
    if token:
      resp = urlfetch.fetch(url=self._GetApiUri()+"/subscriptions",
                            headers={"Authorization": "Bearer "+self._GetToken()},
                            deadline=15)
      data["data"] = resp.content

    self._Render("op/list-subscriptions.html", data)


class OpNewCustomer(BaseHandler):
  # Method needs to be 'get()' since that's what webapp requires.
  # pylint: disable=C6409
  def get(self):
    token = self._GetToken()
    if not token:
      self.redirect("/")
      return

    self._Render("op/new-customer.html", {})

  def post(self):
    token = self._GetToken()
    if not token:
      self.redirect("/")
      return

    request_data = {"kind": "customers#customer",
                    "customerId": self.request.POST.get("customerDomain"),
                    "customerDomain": self.request.POST.get("customerDomain"),
                    "postalAddress": {
                      "kind": "customers#address",
                      "contactName": self.request.POST.get("contactName"),
                      "organizationName": self.request.POST.get("organizationName"),
                      "locality": self.request.POST.get("locality"),
                      "region": self.request.POST.get("region"),
                      "postalCode": self.request.POST.get("postalCode"),
                      "countryCode": self.request.POST.get("countryCode"),
                      "addressLine1": self.request.POST.get("addressLine1"),
                      "addressLine2": self.request.POST.get("addressLine2"),
                      "addressLine3": self.request.POST.get("addressLine3")
                    },
                    "phoneNumber": self.request.POST.get("phoneNumber"),
                    "alternateEmail": self.request.POST.get("alternateEmail")}

    resp = urlfetch.fetch(url=self._GetApiUri()+"/customers",
                          method="POST",
                          payload=json.dumps(request_data),
                          headers={"Authorization": "Bearer "+self._GetToken(),
                                   "Content-Type": "application/json"},
                          deadline=30)
    data = {"request": json.dumps(request_data),
            "response": resp.content,
            "response_code": resp.status_code,
            "response_headers": resp.headers}

    self._Render("op/new-customer-result.html", data)


class OpGetCustomer(BaseHandler):
  def get(self):
    self._Render("op/get-customer.html", {})

  def post(self):
    token = self._GetToken()
    if not token:
      self.redirect("/")
      return

    url = self._GetApiUri()+"/customers/"+self.request.POST.get("customerId")
    resp = urlfetch.fetch(url=url,
                          method="GET",
                          headers={"Authorization": "Bearer "+self._GetToken()},
                          deadline=30)
    data = {"response": resp.content,
            "response_code": resp.status_code,
            "response_headers": resp.headers}
    self._Render("op/get-customer-result.html", data)


class OpChangeSeats(BaseHandler):
  def get(self):
    data = {}
    token = self._GetToken()
    if token:
      resp = urlfetch.fetch(url=self._GetApiUri()+"/subscriptions",
                            headers={"Authorization": "Bearer "+self._GetToken()},
                            deadline=15)
      data["subscriptions"] = json.loads(resp.content)

    self._Render("op/change-seats.html", data)

  def post(self):
    data = {}
    token = self._GetToken()
    if not token:
      self.redirect("/")
      return

    subscription = self.request.POST.get("subscription")
    customerId, subscriptionId = subscription.split(":")

    request_data = {"kind": "subscriptions#seats",
                    "numberOfSeats": self.request.POST.get("numberOfSeats")}
    if self.request.POST.get("maximumNumberOfSeats") != "":
      request_data["maximumNumberOfSeats"] = self.request.POST.get("maximumNumberOfSeats")

    url = self._GetApiUri()+"/customers/"+customerId+"/subscriptions/"+subscriptionId+"/changeSeats"
    resp = urlfetch.fetch(url=url,
                          method="POST",
                          payload=json.dumps(request_data),
                          headers={"Authorization": "Bearer "+self._GetToken(),
                                   "Content-Type": "application/json"},
                          deadline=30)

    data = {"request": json.dumps(request_data),
            "response": resp.content,
            "response_code": resp.status_code,
            "response_headers": resp.headers}
    self._Render("op/change-seats-result.html", data)


class OAuthCallback(BaseHandler):
  """This page is redirected to after the user has granted us access."""

  # Method needs to be 'get()' since that's what webapp requires.
  # pylint: disable=C6409

  def get(self):
    if self.request.get("error"):
      self.redirect("/")
      return

    # do a POST to exchange the code for an access token
    data = dict(code=self.request.get("code"),
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                redirect_uri=urlparse.urljoin(self.request.url,
                                              "/oauth2callback"),
                grant_type="authorization_code")
    response = urlfetch.fetch(url=OAUTH_BASE_URI + "/token",
                              payload=urlencode(data),
                              method="POST",
                              deadline=15)
    data = json.loads(response.content)
    if "error" in data:
      # TODO: handle errors
      self.redirect("/")
      return

    access_token = data["access_token"]
    cookie = "token="+base64.b64encode(xor_string(access_token, XOR_KEY))
    self.response.headers.add_header("Set-Cookie", cookie)
    self.redirect("/")


class Logout(BaseHandler):
  """Logs you out by "forgetting" your token cookie."""

  # Method needs to be 'get()' since that's what webapp requires.
  # pylint: disable=C6409

  def get(self):
    cookie = "token=None"
    self.response.headers.add_header("Set-Cookie", cookie)
    self.redirect("/")


class SandboxSwitch(BaseHandler):
  def post(self):
    useSandbox = self.request.POST.get("use-sandbox")
    if useSandbox == "on":
      cookie = "use-sandbox=yes"
    else:
      cookie = "use-sandbox=no"
    self.response.headers.add_header("Set-Cookie", cookie)
    self.redirect("/")

