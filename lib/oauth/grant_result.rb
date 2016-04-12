module Oauth
  class GrantResult
    def initialize(access_token, refresh_token = nil, user = nil)
      @access_token = access_token
      @refresh_token = refresh_token
      @user = user
    end

    attr_reader :access_token, :user

    def to_bearer_hash
      return {} if access_token.nil?
      {
        refresh_token: @refresh_token.to_s,
        access_token: access_token.jwt_token,
        expires_in: access_token.expires_in,
        scope: access_token.scope,
        token_type: 'Bearer'
      }.reject { |_, v| v.blank? }
    end
  end
end
