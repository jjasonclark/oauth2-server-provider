module Oauth
  module Grant
    class ClientCredentials
      def call(oauth_client, params)
        access_token = oauth_client.create_token(:access_token, params[:scope])
        fail Oauth::Errors::InvalidScopeError if access_token.nil?
        Oauth::GrantResult.new(access_token, nil, nil)
      end
    end

    Oauth.register_grant("client_credentials", Oauth::Grant::ClientCredentials)
  end
end
