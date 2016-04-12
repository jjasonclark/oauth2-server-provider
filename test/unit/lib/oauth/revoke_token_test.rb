require 'test_helper'

module Oauth
  class RevokeTokenTest < ActiveSupport::TestCase
    context 'client tokens' do
      setup do
        @client = create(:oauth_client)
        @request_token = create(:oauth_access_token, oauth_client: @client)
        @auth_header = "Bearer #{@request_token.jwt_token}"
        @now = Time.now.utc
      end

      should 'set expire_at to now for client tokens' do
        revoke_token = create(:oauth_access_token, oauth_client: @client)
        params = { token: revoke_token.jwt_token }
        handler = RevokeToken.new(@auth_header, params)
        Timecop.freeze @now do
          handler.call
        end
        revoke_token.reload

        assert_equal @now.to_i, revoke_token.expire_at.utc.to_i
      end

      should 'not change other clients tokens' do
        client2 = create(:oauth_client)
        revoke_token = create(:oauth_access_token, oauth_client: client2)
        params = { token: revoke_token.jwt_token }
        handler = RevokeToken.new(@auth_header, params)
        before_expire = revoke_token.expire_at.utc.to_i
        Timecop.freeze @now do
          handler.call
        end
        revoke_token.reload

        assert_equal before_expire, revoke_token.expire_at.utc.to_i
      end
    end

    context 'user tokens' do
      setup do
        @client = create(:oauth_client)
        @user = create(:staff_user)
        @request_token = create(:oauth_access_token, oauth_client: @client, user: @user)
        @auth_header = "Bearer #{@request_token.jwt_token}"
        @now = Time.now.utc
      end

      should 'set expire_at to now for user tokens' do
        revoke_token = create(:oauth_access_token, oauth_client: @client, user: @user)
        params = { token: revoke_token.jwt_token }
        handler = RevokeToken.new(@auth_header, params)
        Timecop.freeze @now do
          handler.call
        end
        revoke_token.reload

        assert_equal @now.to_i, revoke_token.expire_at.utc.to_i
      end

      should 'not change other users tokens' do
        user2 = create(:staff_user)
        revoke_token = create(:oauth_access_token, oauth_client: @client, user: user2)
        params = { token: revoke_token.jwt_token }
        handler = RevokeToken.new(@auth_header, params)
        before_expire = revoke_token.expire_at.utc.to_i
        Timecop.freeze @now do
          handler.call
        end
        revoke_token.reload

        assert_equal before_expire, revoke_token.expire_at.utc.to_i
      end
    end
  end
end
