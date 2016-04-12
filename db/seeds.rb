OauthClient.create! do |oc|
  oc.name = 'TestClient'
  oc.client_id = '37b17256f79cfe66f1bffb8c0524e35e'
  oc.client_secret = '856364b48139e26d3dd2eafe35e7ebde'
  oc.redirect_uri = 'http://localhost:5000/oauth_redirect'
end
