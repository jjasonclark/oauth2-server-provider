module Oauth
  class TokenController < ApplicationController
    skip_before_action :verify_authenticity_token
    before_action -> { expires_now }

    def token
      Oauth::CreateToken.new(request.authorization, params).call do |code, body, _|
        render status: code, json: body
      end
    end

    def revoke
      Oauth::RevokeToken.new(request.authorization, params).call
      render nothing: true
    end
  end
end
