module Oauth
  class CreateToken
    def initialize(auth_header, params = {})
      @auth_header = auth_header.to_s
      @params = params || {}
    end

    attr_reader :auth_header, :params

    def call
      fail Oauth::Errors::InvalidClientError if oauth_client.nil?
      result = Oauth.grants[grant_type].new.call(oauth_client, params)
      yield(:ok, result.to_bearer_hash.to_json, result.user) if block_given?
    rescue Oauth::Errors::OauthError => e
      yield(:bad_request, e.error_hash.to_json, nil) if block_given?
    end

    private

    def oauth_client_from_basic_auth
      client_id, client_secret = credentials_from_header.split(/:/, 2)
      find_authorized_client(client_id, client_secret)
    end

    def oauth_client_from_params
      find_authorized_client(params[:client_id], params[:client_secret])
    end

    def find_authorized_client(client_id, client_secret)
      return nil if client_id.blank? || client_secret.blank?
      OauthClient.find_by(client_id: client_id.to_s, client_secret: client_secret.to_s)
    end

    def oauth_client
      @oauth_client ||= oauth_client_from_basic_auth || oauth_client_from_params
    end

    def grant_type
      @grant_type ||= params[:grant_type].to_s
    end

    def credentials_from_header
      ::Base64.decode64(auth_header.split(' ', 2).last || '')
    end
  end
end
