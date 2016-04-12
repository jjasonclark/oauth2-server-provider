# oauth2-server-provider
Oauth2 Provider


# Manual Steps

1. Associate OauthToken with what ever is your user model
  1. Add belongs_to in OauthToken
  1. Add has_many to user model for oauth_tokens
