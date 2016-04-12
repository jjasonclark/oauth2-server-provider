module Oauth
  module Grant
    class Password
      def call(oauth_client, params)
        user = fetch_user(params[:username], params[:password])
        fail Oauth::Errors::InvalidRequestError if user.nil?
        access_token = oauth_client.create_token(:access_token, params[:scope], user)
        fail Oauth::Errors::InvalidScopeError if access_token.nil?
        refresh_token = oauth_client.create_token(:refresh_token, params[:scope], user)
        Oauth::GrantResult.new(access_token, refresh_token.try(:jwt_token), user)
      end

      def fetch_user(email, password)
        User.find_by(email: email).try do |user|
          return user if user.valid_password?(password)
        end
      end
    end

    Oauth.register_grant("password", Oauth::Grant::Password)
  end
end
