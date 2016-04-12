module Oauth
  class TokenFinder
    TOKEN_PREFACE = 'Bearer '.freeze

    def initialize(token_preface = TOKEN_PREFACE)
      @token_preface = token_preface
    end

    def call(auth_header, access_token)
      header_token = access_token_from_header(auth_header)
      param_token = access_token_from_params(access_token)
      return nil if header_token && param_token && header_token != param_token
      header_token || param_token
    end

    private

    def access_token_from_header(auth_header)
      header = auth_header.to_s.strip
      return nil unless header.start_with?(@token_preface)
      auth_value = header[@token_preface.size..-1].strip
      auth_value == '' ? nil : auth_value
    end

    def access_token_from_params(access_token)
      auth_param = access_token.to_s.strip
      auth_param == '' ? nil : auth_param
    end
  end
end
