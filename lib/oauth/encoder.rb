module Oauth
  class Encoder
    TOKEN_ID = 'token'.freeze

    def initialize(algorithm, encrypt_key, decrypt_key = nil)
      @algorithm = algorithm.to_s
      @encrypt_key = encrypt_key.to_s
      @decrypt_key = (decrypt_key || encrypt_key).to_s
    end

    def encode(token, expire_at)
      JWT.encode(
        { TOKEN_ID => token.to_s },
        @encrypt_key,
        @algorithm,
        'nbf' => Time.now.utc.to_i,  # Not before time
        'exp' => expire_at.utc.to_i) # Expire time
    end

    def decode(session_token)
      decoded_token = JWT.decode(
        session_token,
        @decrypt_key,
        true,
        algorithm: @algorithm,
        verify_expiration: true,
        verify_not_before: true)
      decoded_token.first[TOKEN_ID]
    rescue JWT::ImmatureSignature
      Rails.logger.warn("JWT token used before it will become valid: #{session_token}")
      nil
    rescue JWT::ExpiredSignature
      Rails.logger.warn("Expired JWT token used: #{session_token}")
      nil
    rescue JWT::DecodeError
      Rails.logger.warn("Bad JWT token used: #{session_token}")
      nil
    end
  end
end
