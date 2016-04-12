module Oauth
  module Errors
    INVALID_GRANT = { error: 'invalid_grant' }
    INVALID_CLIENT = { error: 'invalid_client' }
    INVALID_SCOPE = { error: 'invalid_scope' }
    INVALID_REQUEST = { error: 'invalid_request' }
    INVALID_REDIRECT = { error: 'Redirect URI is not the same as preregistered' }
    ACCESS_DENIED = { error: 'access_denied' }
    UNAUTHORIZED_CLIENT = { error: 'unauthorized_client' }
    UNSUPPORTED_RESPONSE_TYPE = { error: 'unsupported_response_type' }

    class OauthError < RuntimeError
      def error_hash
        { error: '' }
      end
    end

    class InvalidClientError < OauthError
      def error_hash
        INVALID_CLIENT
      end
    end

    class AccessDeniedError < OauthError
      def error_hash
        ACCESS_DENIED
      end
    end

    class InvalidScopeError < OauthError
      def error_hash
        INVALID_SCOPE
      end
    end

    class InvalidGrantError < OauthError
      def error_hash
        INVALID_GRANT
      end
    end

    class InvalidRequestError < OauthError
      def error_hash
        INVALID_REQUEST
      end
    end

    class InvalidRedirectError < OauthError
      def error_hash
        INVALID_REDIRECT
      end
    end

    class UnauthorizedClientError < OauthError
      def error_hash
        UNAUTHORIZED_CLIENT
      end
    end
  end
end
