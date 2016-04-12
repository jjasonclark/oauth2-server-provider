require 'test_helper'

class OauthClientTest < ActiveSupport::TestCase
  context 'validations' do
    should 'client_id' do
      validate_presence_of :client_id
      validate_uniqueness_of :client_id
    end

    should 'client_secret' do
      validate_presence_of :client_secret
    end
  end

  context '#find_client!' do
    setup do
      @client = create(:oauth_client)
    end

    should 'return found client' do
      found = OauthClient.find_client!(@client.client_id)

      assert_equal @client.id, found.id
    end

    should 'raise if not found' do
      assert_raise ActiveRecord::RecordNotFound do
        OauthClient.find_client!('not_found')
      end
    end

    should 'raise if client is not issuing tokens' do
      @client = create(:oauth_client, issue_tokens: false)
      assert_raise ActiveRecord::RecordNotFound do
        OauthClient.find_client!(@client.client_id)
      end
    end
  end

  context '#find_authorized_client' do
    setup do
      @client = create(:oauth_client)
    end

    should 'return found client' do
      found = OauthClient.find_authorized_client(@client.client_id, @client.client_secret)

      assert_equal @client.id, found.id
    end

    should 'raise if not found' do
      assert_raise ActiveRecord::RecordNotFound do
        OauthClient.find_client!('not_found')
      end
    end

    should 'raise if client is not issuing tokens' do
      @client = create(:oauth_client, issue_tokens: false)
      assert_raise ActiveRecord::RecordNotFound do
        OauthClient.find_client!(@client.client_id)
      end
    end

    should 'return nil if client_secret is blank' do
      found = OauthClient.find_authorized_client(@client.client_id, '')

      assert_nil found
    end

    should 'return nil if client_id is blank' do
      found = OauthClient.find_authorized_client('', @client.client_secret)

      assert_nil found
    end

    should 'return nil if client is not issuing tokens' do
      @client = create(:oauth_client, issue_tokens: false)
      found = OauthClient.find_authorized_client(@client.client_id, @client.client_secret)

      assert_nil found
    end
  end

  context '#all_allowed_scopes?' do
    context 'with scope_whitelist' do
      setup do
        @client = create(:oauth_client, scope_whitelist: '  configuration     create_referral')
      end

      should 'allow a subset' do
        assert @client.all_allowed_scopes?('configuration   ')
      end

      should 'allow a full set out of order' do
        assert @client.all_allowed_scopes?('create_referral    configuration')
      end

      should 'allow duplicates' do
        assert @client.all_allowed_scopes?('configuration configuration')
      end

      should 'disallow extra items' do
        refute @client.all_allowed_scopes?('  notification   configuration create_referral')
      end

      should 'disallow empty set when have a whitelist' do
        refute @client.all_allowed_scopes?('')
      end
    end

    context 'with empty scope_whitelist' do
      setup do
        @client = create(:oauth_client, scope_whitelist: nil)
      end

      should 'allow empty set' do
        assert @client.all_allowed_scopes?('   ')
      end

      should 'disallow all scopes' do
        refute @client.all_allowed_scopes?('configuration')
      end
    end
  end
end
