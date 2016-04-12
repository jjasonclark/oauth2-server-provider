module Oauth
  module Grant
    class AuthorizationCode
      def call(oauth_client, params)
        authorization_code = oauth_client.find_authorization_code(params[:code])
        fail Oauth::Errors::InvalidRequestError if authorization_code.nil?
        fail Oauth::Errors::InvalidGrantError if authorization_code.expired?
        fail Oauth::Errors::InvalidGrantError if authorization_code.oauth_client.redirect_uri.nil?
        if params[:redirect_uri].to_s != "" && authorization_code.oauth_client.redirect_uri != params[:redirect_uri].to_s
          fail Oauth::Errors::InvalidRequestError
        end
        scope = authorization_code.scope
        access_token = oauth_client.create_token(:access_token, scope, authorization_code.user)
        fail Oauth::Errors::InvalidScopeError if access_token.nil?
        refresh_token = oauth_client.create_token(:refresh_token, scope, authorization_code.user)
        authorization_code.expire! # Do not allow code be used again
        Oauth::GrantResult.new(access_token, refresh_token.try(:jwt_token), authorization_code.user)
      end
    end

    Oauth.register_grant("authorization_code", Oauth::Grant::AuthorizationCode)
  end
end
