require 'uri'

module Oauth
  class AuthorizeController < ApplicationController
    before_action -> { expires_now }
    before_action :fetch_oauth_client

    def new
      fail Oauth::Errors::UnauthorizedClientError if @oauth_client.redirect_uri.blank?
      fail Oauth::Errors::InvalidRequestError if params[:response_type] != "code"
      fail Oauth::Errors::InvalidRequestError if params[:redirect_uri].present? && @oauth_client.redirect_uri != params[:redirect_uri]
      @scope = params[:scope]
      @state = params[:state]
      @redirect_uri = @oauth_client.redirect_uri
    rescue Oauth::Errors::OauthError => e
      redirect_to create_redirect_url(@oauth_client.redirect_uri, error: e.error_hash[:error], state: params[:state])
    end

    def create
      fail Oauth::Errors::AccessDeniedError if params[:reject].present? || params[:authorize].blank?
      token = @oauth_client.create_token(:authorization_code, params[:scope], current_user)
      fail Oauth::Errors::InvalidRequestError if token.nil?
      if params[:timeout].present?
        token.update_attribute(:expire_at, Time.now.utc + params[:timeout].to_i.seconds)
      end
      redirect_to create_redirect_url(@oauth_client.redirect_uri, code: token.jwt_token, state: params[:state])
    rescue Oauth::Errors::OauthError => e
      redirect_to create_redirect_url(@oauth_client.redirect_uri, error: e.error_hash[:error], state: params[:state])
    end

    private

    def fetch_oauth_client
      @oauth_client = OauthClient.find_by!(client_id: params[:client_id])
    end

    def create_redirect_url(start_url, extra_params = {})
      redirect_url = URI(start_url)
      out_params = URI.decode_www_form(redirect_url.query || "")
      extra_params.each { |k, v| out_params << [k, v] unless v.blank? }
      redirect_url.query = URI.encode_www_form(out_params)
      redirect_url.to_s
    end
  end
end
