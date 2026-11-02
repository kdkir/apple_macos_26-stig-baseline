# frozen_string_literal: true

require 'json'

# Reads a preference value the same way the DISA check procedures do: through
# NSUserDefaults with the given suite name, evaluated by JavaScript for Automation.
# Values delivered by configuration profiles take precedence, exactly as they do for
# the operating system.
class MacosManagedPreference < Inspec.resource(1)
  name 'macos_managed_preference'
  supports platform: 'darwin'
  desc 'Reads a macOS preference value through NSUserDefaults (as the STIG check procedures do).'
  example <<~EXAMPLE
    describe macos_managed_preference('com.apple.applicationaccess', 'allowAirDrop') do
      its('value') { should cmp false }
    end

    describe macos_managed_preference('com.apple.locationd', 'LocationServicesEnabled', user: '_locationd') do
      its('value') { should cmp false }
    end
  EXAMPLE

  attr_reader :suite, :key

  # InSpec passes resource arguments positionally, so options arrive as a Hash.
  def initialize(suite, key, opts = {})
    @suite = suite
    @key = key
    @user = opts[:user]
  end

  # Native Ruby value (true/false/Integer/String/Array/Hash), or nil when the key is not set.
  def value
    return @value if defined?(@value)

    @value = read_value
  end

  def set?
    !value.nil?
  end

  def to_s
    "macOS preference #{@suite} #{@key}"
  end

  private

  def read_value
    script = "JSON.stringify({v: ObjC.deepUnwrap($.NSUserDefaults.alloc.initWithSuiteName(#{@suite.to_json}).objectForKey(#{@key.to_json}))})"
    cmd = "/usr/bin/osascript -l JavaScript -e '#{script}'"
    cmd = "/usr/bin/sudo -u #{@user} #{cmd}" if @user
    result = inspec.command(cmd)

    unless result.exit_status.zero?
      raise Inspec::Exceptions::ResourceFailed,
            "osascript failed reading #{@suite} #{@key}: #{result.stderr.strip}"
    end

    JSON.parse(result.stdout.strip)['v']
  rescue JSON::ParserError
    raise Inspec::Exceptions::ResourceFailed,
          "Unexpected osascript output reading #{@suite} #{@key}: #{result.stdout.strip}"
  end
end
