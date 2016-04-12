require 'test_helper'

class OauthTokenTest < ActiveSupport::TestCase
  context 'validate expire_at' do
    should 'valid expires in the future' do
      token = build(:oauth_access_token, expire_at: 10.days.since.utc)

      token.save

      assert_empty token.errors.full_messages
    end

    should 'not valid if already expired' do
      token = build(:oauth_access_token, expire_at: 10.days.ago.utc)

      token.save

      assert_not_empty token.errors.full_messages
    end
  end

  context '#create_for_client!' do
    setup do
      @client = create(:oauth_client)
      Oauth.configuration.stubs(timeout_for: 10)
    end

    should 'return nil if timeout is 0' do
      Oauth.configuration.stubs(timeout_for: 0)

      result = OauthToken.create_for_client!(@client, :access_token, 'blah')

      refute result
    end

    should 'use UTC for expire_at' do
      result = OauthToken.create_for_client!(@client, :access_token, 'blah')

      assert_equal result.expire_at.utc, result.expire_at
    end

    should 'raise InvalidRequestError if unknown type' do
      assert_raise Oauth::Errors::InvalidRequestError do
        OauthToken.create_for_client!(@client, :blah, 'blah')
      end
    end

    should 'create a token' do
      assert_difference 'OauthToken.count' do
        OauthToken.create_for_client!(@client, :access_token, 'blah')
      end
    end
  end

  context "#containing_oauth_scope" do
    should "work with many scopes" do
      client = create(:oauth_client, scope_whitelist: 'foo bar')
      token = create(:oauth_access_token, oauth_client: client, scope: 'bar')

      results = OauthToken.containing_oauth_scope('bar')

      assert_equal [token], results
    end

    should "work with scopes with single quotes in the name" do
      client = create(:oauth_client, scope_whitelist: "foo' bar")
      token = create(:oauth_access_token, oauth_client: client, scope: "foo'")

      results = OauthToken.containing_oauth_scope("foo'")

      assert_equal [token], results
    end

    should "work with scopes with double quotes in the name" do
      client = create(:oauth_client, scope_whitelist: 'foo" bar')
      token = create(:oauth_access_token, oauth_client: client, scope: 'foo"')

      results = OauthToken.containing_oauth_scope('foo"')

      assert_equal [token], results
    end

    should "work with scopes with % in the name" do
      client = create(:oauth_client, scope_whitelist: 'foo foo% f%oo %foo')
      create(:oauth_access_token, oauth_client: client, scope: 'foo')
      create(:oauth_access_token, oauth_client: client, scope: 'foo%')
      create(:oauth_access_token, oauth_client: client, scope: 'f%oo')
      create(:oauth_access_token, oauth_client: client, scope: '%foo')
      create(:oauth_access_token, oauth_client: client, scope: 'foo foo% f%oo %foo')

      assert_equal ['foo%', 'foo foo% f%oo %foo'], OauthToken.containing_oauth_scope('foo%').map(&:scope)
      assert_equal ['f%oo', 'foo foo% f%oo %foo'], OauthToken.containing_oauth_scope('f%oo').map(&:scope)
      assert_equal ['%foo', 'foo foo% f%oo %foo'], OauthToken.containing_oauth_scope('%foo').map(&:scope)
      assert_equal ["foo", "foo%", "%foo", "foo foo% f%oo %foo"], OauthToken.containing_oauth_scope('foo').map(&:scope)
    end
  end
end
