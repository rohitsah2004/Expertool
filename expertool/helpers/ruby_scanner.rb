# Trusted adapter: proxy credentials are read from environment into Ruby's in-memory
# ARGV, never OS command arguments, a config file, or an evidence record.
require 'uri'
path = ARGV.shift
scanner = ENV.fetch('EXPERTOOL_SCANNER')
proxy = URI(ENV.fetch('HTTPS_PROXY'))
credentials = URI.decode_www_form_component(proxy.user.to_s) + ':' + URI.decode_www_form_component(proxy.password.to_s)
case scanner
when 'whatweb'
  # WhatWeb 0.6.4 converts its regex capture array to an inspected string
  # when parsing --proxy-user. Keep the intended password in this process.
  # WhatWeb resolves its target for display before opening the proxy. Supply
  # only the already-authorized IPv4 metadata; all routing stays at the proxy,
  # which independently re-resolves and checks every admitted request.
  require 'resolv'
  require 'json'
  approved_dns = JSON.parse(ENV.fetch('EXPERTOOL_DNS_MAP'))
  approved_dns.values.dup.each { |ip| approved_dns[ip] = ip }
  approved_dns[proxy.host] = proxy.host
  resolver = Module.new do
    define_method(:getaddress) do |name|
      approved_dns.fetch(name) { raise Resolv::ResolvError, 'Host outside adapter DNS snapshot' }
    end
  end
  Resolv.singleton_class.prepend(resolver)
  proxy_password = URI.decode_www_form_component(proxy.password.to_s)
  trace_var(:$PROXY_PASS) { $PROXY_PASS = proxy_password }
  ARGV.unshift('--proxy', proxy.host + ':' + proxy.port.to_s, '--proxy-user', credentials)
when 'wpscan'
  ARGV.unshift('--proxy', proxy.scheme + '://' + proxy.host + ':' + proxy.port.to_s, '--proxy-auth', credentials)
else
  raise 'Unsupported scanner'
end
$0 = path
load path
