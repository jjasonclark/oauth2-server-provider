require 'test_helper'

module Oauth
  class TokenFinderTest < ActiveSupport::TestCase
    context 'finds token' do
      should 'fetch from header' do
        params = {}
        access_token = TokenFinder.new.call('Bearer 1234', nil)

        assert_equal '1234', access_token
      end

      should 'fetch from params' do
        access_token = TokenFinder.new.call(nil, '5678')

        assert_equal '5678', access_token
      end

      should 'allow headers and params if same' do
        access_token = TokenFinder.new.call('Bearer 1234', '1234')

        assert_equal '1234', access_token
      end

      should 'not allow header and params to be different' do
        access_token = TokenFinder.new.call('Bearer 1234', '5678')

        assert_nil access_token
      end

      should 'require bearer token type' do
        access_token = TokenFinder.new.call('Token Token=1234', nil)

        assert_nil access_token
      end
    end
  end
end
