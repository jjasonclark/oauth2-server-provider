module Oauth
  class RevokeToken
    def initialize(auth_header, params)
      @auth_header = auth_header
      @params = params
    end

    attr_reader :auth_header, :params

    def call
      token_param = params[:token]
      return if token_param.blank?
      oauth_access_token = find_access_token
      found_token = oauth_access_token.try(:oauth_client).try(:find_access_token, token_param)
      if found_token && same_user?(oauth_access_token.user, found_token.user)
        found_token.expire!
      end
    end

    private

    def same_user?(left, right)
      (left.nil? && right.nil?) ||
        (left.present? && right.present? && left.id == right.id)
    end

    def find_access_token
      OauthToken.find_from_token(Oauth::TokenFinder.new.call(auth_header, params[:access_token]))
    end
  end
end
