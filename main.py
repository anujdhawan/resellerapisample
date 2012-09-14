# Copyright 2012 Google Inc. All Rights Reserved.

"""Main entry-point for our app."""

__author__ = 'Dean Harding <deanh@google.com>'

import webapp2

import handlers

app = webapp2.WSGIApplication([("/", handlers.MainHandler),
                               ("/oauth2callback", handlers.OAuthCallback),
                               ("/logout", handlers.Logout),
                               ("/sandbox-switch", handlers.SandboxSwitch),
                               ("/op/list-subscriptions", handlers.OpListSubscriptions),
                               ("/op/new-customer", handlers.OpNewCustomer)],
                              debug=True)

