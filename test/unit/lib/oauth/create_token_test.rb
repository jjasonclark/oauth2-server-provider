require 'test_helper'

module Oauth
  class CreateTokenTest < ActiveSupport::TestCase
    def setup
      @client = create(:oauth_client, scope_whitelist: 'create_referral notifications configuration')
    end

    context 'invalid_client' do
      context 'basic auth' do
        should 'returns error if client not found' do
          handler = CreateToken.new(auth_as('not', 'found'),
            grant_type: 'client_credentials')

          handler.call(&error_check('invalid_client'))
        end

        should 'returns error if client secret is wrong' do
          handler = CreateToken.new(auth_as(@client.client_id, 'blah'),
            grant_type: 'refresh_token')

          handler.call(&error_check('invalid_client'))
        end
      end

      context 'params auth' do
        should 'returns error if client not found' do
          handler = CreateToken.new('',
            grant_type: 'password', client_id: 'not', client_secret: 'found')

          handler.call(&error_check('invalid_client'))
        end

        should 'returns error if client secret is wrong' do
          handler = CreateToken.new('',
            grant_type: 'password', client_id: @client.client_id, client_secret: 'blah')

          handler.call(&error_check('invalid_client'))
        end
      end
    end

    context 'unknown grant type' do
      should 'returns error' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'blah')

        handler.call(&error_check('invalid_grant'))
      end
    end

    context 'client credentials grant type' do
      should 'access token hash' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'client_credentials', scope: 'configuration')

        handler.call do |code, body, user|
          assert_equal :ok, code
          json_body = JSON.parse(body)
          assert_equal 'Bearer', json_body['token_type']
          refute_empty json_body['access_token']
          assert json_body['expires_in'] > 0
          refute json_body.key?('refresh_token')
          assert_equal 'configuration', json_body['scope']
          refute user
        end
      end

      should 'not create a refresh token' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'client_credentials', scope: 'configuration')


        assert_difference 'OauthToken.refresh_token.count', 0 do
          handler.call
        end
      end
    end

    context 'refresh token grant type' do
      setup do
        timeout_hash = {
          'user' => {
            'access_token' => 1.hour,
            'refresh_token' => 1.hour
          }
        }
        Oauth.configuration.timeouts['inscope'] = timeout_hash
        Oauth.configuration.timeouts['outofscope'] = timeout_hash
        @client.scope_whitelist = 'configuration inscope'
        @client.save!
      end

      should 'returns error if refresh token is not found' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'refresh_token', refresh_token: 'not found')

        handler.call(&error_check('invalid_request'))
      end

      should 'returns error if scope is different' do
        user = create(:confirmed_staff_user)
        refresh_token = @client.create_token(:refresh_token, 'inscope', user)
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'refresh_token', refresh_token: refresh_token.jwt_token, scope: 'outofscope')

        handler.call(&error_check('invalid_scope'))
      end

      should 'returns error if expired' do
        user = create(:confirmed_staff_user)
        refresh_token = @client.create_token(:refresh_token, 'inscope', user)
        Time.stubs(now: refresh_token.expire_at + 10.days)
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'refresh_token', refresh_token: refresh_token.jwt_token)

        handler.call(&error_check('invalid_grant'))
      end

      should 'access token hash' do
        user = create(:confirmed_staff_user)
        refresh_token = @client.create_token(:refresh_token, 'configuration', user)
        refresh_jwt_token = refresh_token.jwt_token
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'refresh_token', refresh_token: refresh_jwt_token)

        handler.call do |code, body, returned_user|
          assert_equal :ok, code
          json_body = JSON.parse(body)
          assert_equal 'Bearer', json_body['token_type']
          refute_empty json_body['access_token']
          assert json_body['expires_in'] > 0
          assert_equal refresh_jwt_token, json_body['refresh_token']
          assert_equal 'configuration', json_body['scope']
          assert_equal user.id, returned_user.id
        end
      end

      should 'not create a new refresh token' do
        user = create(:confirmed_staff_user)
        refresh_token = @client.create_token(:refresh_token, 'configuration', user)
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'refresh_token', refresh_token: refresh_token.jwt_token)

        assert_difference 'OauthToken.refresh_token.count', 0 do
          handler.call
        end
      end
    end

    context 'password grant type' do
      setup do
        @user = create(:confirmed_staff_user, :with_credentials)
      end

      should 'be and invalid request if email not found' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'password', username: 'not the one', password: 'Cambridge02141', scope: 'notifications')

        handler.call(&error_check('invalid_request'))
      end

      should 'returns error if username and password do not authenticate' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'password', username: @user.email, password: 'not it', scope: 'create_referral')

        handler.call(&error_check('invalid_request'))
      end

      should 'access token hash' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'password', username: @user.email, password: Security::TEST_PASSWORD, scope: 'notifications')

        handler.call do |code, body, user|
          assert_equal :ok, code
          json_body = JSON.parse(body)
          assert_equal 'Bearer', json_body['token_type']
          refute_empty json_body['access_token']
          assert json_body['expires_in'] > 0
          assert_equal 'notifications', json_body['scope']
          assert_equal @user.id, user.id
        end
      end

      should 'include a refresh token' do
        handler = CreateToken.new(auth_as(@client.client_id, @client.client_secret),
          grant_type: 'password', username: @user.email, password: Security::TEST_PASSWORD, scope: 'configuration')

        handler.call do |code, body, user|
          json_body = JSON.parse(body)
          refute json_body['refresh_token'].blank?
        end
      end
    end

    def error_check(error_code)
      proc do |code, body, user|
        assert_equal :bad_request, code
        json_body = JSON.parse(body)
        assert_equal error_code, json_body['error']
        refute user
      end
    end

    def auth_as(client_id, client_secret)
      token = ::Base64.encode64([client_id, client_secret].join(':'))
      "Basic #{token}"
    end
  end
end
