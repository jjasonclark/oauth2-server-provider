require 'oauth'
require 'yaml'
require 'erb'

Oauth.configure do |config|
  config_path = Rails.root.join('config', 'oauth_server.yml')
  config_yaml = YAML.load(ERB.new(File.read(config_path)).result(binding))
  config_yaml[Rails.env.to_s].each { |k, v| config.send "#{k}=", v }

  timeouts_file = Rails.root.join('config', 'oauth_timeouts.yml')
  config.timeouts = YAML.load(ERB.new(File.read(timeouts_file)).result(binding))
end
