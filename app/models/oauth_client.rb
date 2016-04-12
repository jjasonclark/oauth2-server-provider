class OauthClient < ActiveRecord::Base
  before_validation do
    generate_client_id unless client_id
    generate_client_secret unless client_secret
  end

  validates :client_id, presence: true, uniqueness: true
  validates :client_secret, presence: true

  has_many :oauth_tokens, inverse_of: :oauth_client

  def find_access_token(access_token)
    oauth_tokens.access_token.with_token(access_token).first
  end

  def find_refresh_token(refresh_token)
    oauth_tokens.refresh_token.with_token(refresh_token).first
  end

  def find_authorization_code(code)
    oauth_tokens.authorization_code.with_token(code).first
  end

  def create_token(type, scope, user = nil)
    OauthToken.create_for_client!(self, type, scope, user)
  end

  def generate_client_id
    loop do
      self.client_id = SecureRandom.hex
      break unless OauthClient.exists?(client_id: client_id)
    end
  end

  def generate_client_secret
    self.client_secret = SecureRandom.hex
  end
end
