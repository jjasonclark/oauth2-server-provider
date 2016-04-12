class OauthToken < ActiveRecord::Base
  ACCESS_TYPE = 'AccessToken'
  REFRESH_TYPE = 'RefreshToken'
  AUTHORIZATION_CODE = 'AuthorizationCode'
  TOKEN_TYPES = {
    refresh_token: REFRESH_TYPE,
    authorization_code: AUTHORIZATION_CODE,
    access_token: ACCESS_TYPE
  }

  belongs_to :oauth_client, inverse_of: :oauth_tokens
  belongs_to :user, inverse_of: :oauth_tokens

  validates :oauth_client_id, presence: true
  validates :kind, presence: true, inclusion: TOKEN_TYPES.values
  validate :expire_in_future

  scope :not_expired, ->(on = Time.now.utc) { where('expire_at >= ?', on) }
  scope :with_token, ->(token) { where(id: Array(token).map { |x| Oauth.decode_jwt(x) }) }
  scope :access_token, -> { where(kind: ACCESS_TYPE) }
  scope :refresh_token, -> { where(kind: REFRESH_TYPE) }
  scope :authorization_code, -> { where(kind: AUTHORIZATION_CODE) }

  def scopes
    @scopes ||= Array((scope || '').split(' '))
  end

  def valid_scope?(checked_scopes)
    Array(checked_scopes).all? { |scope_name| scopes.include? scope_name.to_s }
  end

  def expire!(now = Time.now.utc)
    update_attribute(:expire_at, now || Time.now.utc)
  end

  def expired?
    expire_at <= Time.now.utc
  end

  def expires_in
    return 0 unless expire_at
    [0, expire_at.utc.to_i - Time.now.utc.to_i].max
  end

  def expire_in_future
    return if expire_at > Time.now.utc
    errors.add :expire_at, 'must expire in the future'
  end

  def jwt_token
    @jwt_token ||= Oauth.encode_jwt(id, expire_at)
  end

  def authorize!(allowed_scopes)
    result = Array(allowed_scopes).any? { |scope_name| scopes.include? scope_name.to_s }
    fail Oauth::Errors::AccessDeniedError unless result
  end

  class << self
    def find_from_token(access_token)
      preload(:oauth_client).
        preload(:user).
        access_token.
        not_expired.
        with_token(access_token).
        first
    end

    def create_for_client!(oauth_client, type, scope = nil, user = nil)
      access_scope = scope.presence || Oauth.configuration.default_scope
      requester = user ? :user : :client
      timeout = Oauth.configuration.timeout_for(type, requester, access_scope)
      return nil unless timeout > 0
      token_type = TOKEN_TYPES.fetch(type) { fail Oauth::Errors::InvalidRequestError }
      expire = Time.now.utc + timeout.seconds
      oauth_client.oauth_tokens.create(
        user: user,
        expire_at: expire,
        scope: access_scope,
        kind: token_type)
    end
  end
end
