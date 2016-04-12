module Oauth
  module Grant
    class RefreshToken
      def call(oauth_client, params)
        refresh_token = oauth_client.find_refresh_token(params[:refresh_token])
        fail Oauth::Errors::InvalidRequestError if refresh_token.nil?
        fail Oauth::Errors::InvalidGrantError if refresh_token.expired?
        scope = params[:scope] || refresh_token.scope
        fail Oauth::Errors::InvalidScopeError unless refresh_token.valid_scope?(scope)
        access_token = oauth_client.create_token(:access_token, scope, refresh_token.user)
        fail Oauth::Errors::InvalidScopeError if access_token.nil?
        Oauth::GrantResult.new(access_token, params[:refresh_token], refresh_token.user)
      end
    end

    Oauth.register_grant("refresh_token", Oauth::Grant::RefreshToken)
  end
end
