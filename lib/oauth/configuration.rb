module Oauth
  class Configuration
    class << self
      def lazy_property(name, default)
        setter = "#{name}=".freeze
        variable_name = "@#{name}".freeze
        define_method(setter) do |value|
          instance_variable_set variable_name, value
        end
        define_method(name) do
          current = instance_variable_get variable_name
          return current if current
          instance_variable_set variable_name, default
          default
        end
      end
    end

    lazy_property :default_scope, nil
    lazy_property :client_id, nil
    lazy_property :client_secret, nil
    lazy_property :sign_token, nil
    lazy_property :verify_token, nil
    lazy_property :algorithm, nil
    lazy_property :timeouts, nil

    def timeout_for(type, requester, scope)
      timeout_calculator.call(type, requester, scope)
    end

    def timeout_calculator
      @timeout_calculator ||= TimeoutCalculator.new(timeouts)
    end
  end
end
