# frozen_string_literal: true

# Account policies reported by `pwpolicy getaccountpolicies` (global, or for one user).
class MacosPwpolicy < Inspec.resource(1)
  name 'macos_pwpolicy'
  supports platform: 'darwin'
  desc 'Parsed macOS account policies from `pwpolicy -getaccountpolicies`.'
  example <<~EXAMPLE
    describe macos_pwpolicy do
      its('max_failed_authentications') { should all be <= 3 }
    end
  EXAMPLE

  def initialize(user = nil)
    @user = user
  end

  # The parsed policy dictionary (empty when no policy is set).
  def policies
    return @policies if defined?(@policies)

    cmd = @user ? "/usr/bin/pwpolicy -u #{@user} getaccountpolicies" : '/usr/bin/pwpolicy -getaccountpolicies'
    @policies = MacosPlist.parse(inspec.command(cmd).stdout) || {}
  end

  # Every integer value stored under +key+ anywhere in the policy (policy parameters).
  def integers(key)
    MacosPlist.find_values(policies, key).select { |v| v.is_a?(Integer) }
  end

  def policy_contents
    MacosPlist.find_values(policies, 'policyContent').map(&:to_s)
  end

  def policy_identifiers
    MacosPlist.find_values(policies, 'policyIdentifier').map(&:to_s)
  end

  # Policy entries (hashes) in the given category, e.g. 'policyCategoryAuthentication'.
  def category(name)
    Array(policies[name])
  end

  def max_failed_authentications
    integers('policyAttributeMaximumFailedAuthentications')
  end

  def auto_enable_in_seconds
    integers('autoEnableInSeconds')
  end

  def expires_every_n_days
    integers('policyAttributeExpiresEveryNDays')
  end

  def minimum_lifetime_hours
    integers('policyAttributeMinimumLifetimeHours')
  end

  def inactive_days
    integers('policyAttributeInactiveDays')
  end

  # Largest N among password content rules of the form "policyAttributePassword matches '.{N,".
  def minimum_length
    policy_contents.flat_map { |c| c.scan(/policyAttributePassword matches '\.\{(\d+),/).flatten.map(&:to_i) }.max
  end

  # Largest N among rules of the form "policyAttributePassword matches '(.*[^a-zA-Z0-9].*){N}".
  def minimum_special_characters
    policy_contents.flat_map { |c| c.scan(/policyAttributePassword matches '\(\.\*\[\^a-zA-Z0-9\]\.\*\)\{(\d+)/).flatten.map(&:to_i) }.max
  end

  def to_s
    @user ? "pwpolicy for #{@user}" : 'pwpolicy global account policies'
  end
end
