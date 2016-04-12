module Oauth
  class TimeoutCalculator
    def initialize(config)
      @scope_config = config
    end

    attr_reader :scope_config

    def call(type, requester, scope)
      scopes = scopes_array(scope)
      access_type = requester.to_s
      token_type = type.to_s
      timeouts(scopes, access_type, token_type).map do |value|
        value[access_type][token_type].to_i
      end.min
    end

    def scopes_array(scope)
      scope.to_s.split(' ')
    end

    def timeouts(scopes, access_type, token_type)
      scope_config.select do |key, value|
        scopes.include?(key) &&
        value.key?(access_type) &&
        value[access_type].key?(token_type)
      end.values
    end
  end
end
