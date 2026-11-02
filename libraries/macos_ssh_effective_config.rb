# frozen_string_literal: true

# Shared parser for `sshd -G` / `ssh -G` output: one lowercase keyword per line followed
# by its value. Keywords that appear more than once (e.g. hostkey) are kept as arrays.
module MacosSshEffectiveConfigParser
  # FIPS-compliant algorithm settings required by the STIG for both sshd and ssh.
  FIPS_ALGORITHMS = {
    'ciphers' => 'aes128-gcm@openssh.com',
    'hostbasedacceptedalgorithms' => 'ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com',
    'hostkeyalgorithms' => 'ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com',
    'kexalgorithms' => 'ecdh-sha2-nistp256',
    'macs' => 'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',
    'pubkeyacceptedalgorithms' => 'ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com',
    'casignaturealgorithms' => 'ecdsa-sha2-nistp256,sk-ecdsa-sha2-nistp256@openssh.com',
  }.freeze

  def params
    return @params if defined?(@params)

    result = inspec.command(effective_config_command)
    unless result.exit_status.zero?
      raise Inspec::Exceptions::ResourceFailed,
            "`#{effective_config_command}` failed: #{result.stderr.strip}"
    end

    @params = {}
    result.stdout.each_line do |line|
      keyword, value = line.strip.split(/\s+/, 2)
      next if keyword.nil? || keyword.empty?

      keyword = keyword.downcase
      value = value.to_s
      @params[keyword] = @params.key?(keyword) ? Array(@params[keyword]) + [value] : value
    end
    @params
  end

  def [](keyword)
    params[keyword.to_s.downcase]
  end
end

class MacosSshdEffectiveConfig < Inspec.resource(1)
  name 'sshd_effective_config'
  supports platform: 'darwin'
  desc 'The effective SSH daemon configuration as reported by `sshd -G`.'
  example <<~EXAMPLE
    describe sshd_effective_config do
      its(['clientaliveinterval']) { should cmp 900 }
    end
  EXAMPLE

  include MacosSshEffectiveConfigParser

  def effective_config_command
    '/usr/sbin/sshd -G'
  end

  def to_s
    'sshd effective configuration'
  end
end

class MacosSshEffectiveConfig < Inspec.resource(1)
  name 'ssh_effective_config'
  supports platform: 'darwin'
  desc 'The effective SSH client configuration for a user as reported by `ssh -G`.'
  example <<~EXAMPLE
    describe ssh_effective_config('jdoe') do
      its(['serveraliveinterval']) { should cmp 900 }
    end
  EXAMPLE

  include MacosSshEffectiveConfigParser

  def initialize(user)
    @user = user
  end

  def effective_config_command
    "/usr/bin/sudo -u #{@user} /usr/bin/ssh -G ."
  end

  def to_s
    "ssh effective configuration for #{@user}"
  end
end
