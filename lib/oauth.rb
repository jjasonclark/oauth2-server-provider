require_relative 'oauth/configuration'
require_relative 'oauth/create_token'
require_relative 'oauth/encoder'
require_relative 'oauth/errors'
require_relative 'oauth/grant_result'
require_relative 'oauth/revoke_token'
require_relative 'oauth/timeout_calculator'
require_relative 'oauth/token_finder'

module Oauth
  class << self
    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield configuration if block_given?
    end

    def encoder
      @encoder ||= Encoder.new(configuration.algorithm, configuration.sign_token, configuration.verify_token)
    end

    def encode_jwt(access_token, expire_at = Time.now.utc)
      return nil unless access_token.present?
      encoder.encode(access_token, expire_at)
    end

    def decode_jwt(access_token)
      return nil unless access_token.present?
      encoder.decode(access_token)
    end

    def grants
      @grants ||= Hash.new { fail Oauth::Errors::InvalidGrantError }
    end

    def register_grant(name, handler)
      grants[name] = handler
    end
  end
end
require_relative 'oauth/grant/authorization_code'
require_relative 'oauth/grant/client_credentials'
require_relative 'oauth/grant/password'
require_relative 'oauth/grant/refresh_token'
